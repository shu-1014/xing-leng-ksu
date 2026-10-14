"""Validate the complete LKM matrix before creating downloadable release names."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]


def read_properties(path):
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key.strip() in result:
            raise ValueError(f"Malformed or duplicate property in {path}: {key}")
        result[key.strip()] = value.strip()
    return result


def read_version(path):
    properties = read_properties(path)
    name = properties.get("KSU_VERSION_NAME", "")
    code = properties.get("KSU_VERSION_CODE", "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?", name):
        raise ValueError("KSU_VERSION_NAME must contain a three-part version and an optional safe revision suffix")
    if not code.isdigit() or not 1 <= int(code) <= 2_100_000_000:
        raise ValueError("KSU_VERSION_CODE must be a positive Android version code")
    return {"name": name, "code": int(code)}


def load_targets(path=ROOT / "scripts/lkm-targets.json"):
    targets = json.loads(path.read_text(encoding="utf-8"))
    kmis = targets.get("kmis", [])
    architectures = targets.get("architectures", {})
    if targets.get("schema_version") != 1 or not kmis or len(kmis) != len(set(kmis)):
        raise ValueError("Invalid or duplicate KMI targets")
    if not all(re.fullmatch(r"android[0-9]+-[0-9]+\.[0-9]+", kmi) for kmi in kmis):
        raise ValueError("Invalid KMI name")
    if architectures != {"aarch64": 183, "x86_64": 62}:
        raise ValueError("The LKM matrix must include AArch64 and x86_64 ELF machines")
    return targets


def validate_identity_inputs():
    package = os.environ.get("PACKAGE_NAME", "")
    size = os.environ.get("EXPECTED_SIZE", "")
    digest = os.environ.get("EXPECTED_HASH", "")
    if package and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package):
        raise ValueError("Invalid public Manager package name")
    if bool(size) != bool(digest):
        raise ValueError("Certificate size and SHA-256 must be supplied together")
    if size:
        if not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", size):
            raise ValueError("Invalid certificate size")
        if not 1 <= int(size, 16 if size.startswith("0x") else 10) <= 1024:
            raise ValueError("Certificate size exceeds the kernel verifier limit")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Certificate SHA-256 must be 64 lowercase hexadecimal digits")


def require_file(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise ValueError(f"Missing, empty, or linked artifact: {path}")
    return path


def validate_elf(path, machine, allowed_types=(1,)):
    require_file(path)
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError(f"Not a little-endian ELF64 artifact: {path}")
    elf_type, actual_machine, version = struct.unpack_from("<HHI", header, 16)
    header_size = struct.unpack_from("<H", header, 52)[0]
    if actual_machine != machine or elf_type not in allowed_types or version != 1 or header_size != 64:
        raise ValueError(f"Wrong ELF architecture, type, or header in {path}: machine={actual_machine}, type={elf_type}")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_lkm(artifacts, targets):
    expected = {
        f"{arch}-{kmi}-lkm"
        for arch in targets["architectures"]
        for kmi in targets["kmis"]
    }
    actual = {path.name for path in artifacts.glob("*-android*-lkm")}
    if actual != expected:
        raise ValueError(f"Incomplete LKM artifact matrix; missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")
    records = []
    for arch, machine in targets["architectures"].items():
        for kmi in targets["kmis"]:
            folder = artifacts / f"{arch}-{kmi}-lkm"
            source = folder / f"{kmi}_kernelsu.ko"
            if sorted(path.name for path in folder.glob("*.ko")) != [source.name]:
                raise ValueError(f"Expected exactly one named kernel module in {folder}")
            validate_elf(source, machine)
            records.append({
                "source": source,
                "filename": f"lkm-{arch}-{kmi}_kernelsu.ko",
                "architecture": arch,
                "elf_machine": machine,
                "kmi": kmi,
                "size": source.stat().st_size,
                "sha256": sha256(source),
            })
    return records


def prepare_output(output):
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError(f"Output must be a new or empty directory: {output}")
    output.mkdir(parents=True, exist_ok=True)


def write_collection(records, output, manifest_name, version, extra=None):
    prepare_output(output)
    files = []
    for record in sorted(records, key=lambda item: item["filename"]):
        shutil.copy2(record["source"], output / record["filename"])
        files.append({key: value for key, value in record.items() if key != "source"})
    manifest = {"schema_version": 1, "version": version, "artifact_count": len(files), "files": files}
    if extra:
        manifest.update(extra)
    (output / manifest_name).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / "SHA256SUMS").write_text(
        "".join(f"{item['sha256']}  {item['filename']}\n" for item in files), encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--targets", type=Path, default=ROOT / "scripts/lkm-targets.json")
    parser.add_argument("--version-file", type=Path, default=ROOT / "version.properties")
    parser.add_argument("--print-kmis", action="store_true")
    args = parser.parse_args()
    targets = load_targets(args.targets)
    if args.print_kmis:
        validate_identity_inputs()
        print("kmis=" + json.dumps(targets["kmis"], separators=(",", ":")))
        return
    if not args.artifacts or not args.output:
        parser.error("--artifacts and --output are required when collecting modules")
    records = inspect_lkm(args.artifacts, targets)
    write_collection(records, args.output, "lkm-manifest.json", read_version(args.version_file))
    print(f"Validated and collected {len(records)} kernel modules in {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"LKM collection failed: {error}", file=sys.stderr)
        sys.exit(1)
