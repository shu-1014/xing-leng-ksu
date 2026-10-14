"""Fail before packaging ksud if flash assets are missing or mismatched."""

import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lkm_collector", ROOT / "scripts/collect-lkm.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def modinfo(path):
    data = path.read_bytes()
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, names_index = struct.unpack_from("<HHH", data, 58)
    if size != 64 or not count or names_index >= count or offset + size * count > len(data):
        raise ValueError(f"Invalid ELF sections: {path}")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size) for i in range(count)]
    names_section = sections[names_index]
    names = data[names_section[4]:names_section[4] + names_section[5]]
    for section in sections:
        name_offset = section[0]
        if name_offset >= len(names):
            raise ValueError(f"Invalid ELF section name: {path}")
        name = names[name_offset:].split(b"\0", 1)[0]
        if name == b".modinfo":
            start, length = section[4:6]
            if start + length > len(data):
                raise ValueError(f"Truncated .modinfo: {path}")
            return dict(entry.split(b"=", 1) for entry in data[start:start + length].split(b"\0") if b"=" in entry)
    raise ValueError(f"Missing .modinfo: {path}")


def verify(root, arch):
    arch = arch.removesuffix("-linux-android")
    targets = collector.load_targets()
    machines = dict(targets["architectures"], riscv64=243)
    if arch not in machines:
        raise ValueError(f"Unsupported architecture: {arch}")
    directory = root / arch
    collector.validate_elf(directory / "ksuinit", machines[arch], (2, 3))
    names = ["ksuinit"]
    if arch != "riscv64":
        expected = {f"{kmi}_kernelsu.ko" for kmi in targets["kmis"]}
        actual = {path.name for path in directory.glob("*.ko")}
        if actual != expected:
            raise ValueError(f"Incomplete KMI matrix for {arch}: missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")
        for kmi in targets["kmis"]:
            name = f"{kmi}_kernelsu.ko"
            path = directory / name
            collector.validate_elf(path, machines[arch])
            info = modinfo(path)
            kernel = kmi.split("-", 1)[1].encode()
            vermagic = info.get(b"vermagic", b"")
            # DDK UTS_RELEASE may be e.g. 6.1.166-dirty without an Android
            # suffix. The selected DDK image identifies the Android KMI;
            # modinfo can verify its kernel branch, not that missing suffix.
            if not vermagic.startswith(kernel + b"."):
                raise ValueError(f"KMI/vermagic mismatch in {path}: {vermagic!r}")
            if info.get(b"name") != b"kernelsu":
                raise ValueError(f"Incorrect kernel module name: {path}")
            names.append(name)
    return {"architecture": arch, "assets": [{"name": name, "sha256": collector.sha256(directory / name)} for name in names]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--root", type=Path, default=ROOT / "userspace/ksud/bin")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.root, args.arch)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Verified {len(result['assets'])} flash assets for {result['architecture']}")
    except (OSError, ValueError, struct.error) as error:
        print(f"Release assets rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
