"""Reject incomplete or mismatched releases before uploading any public assets."""

import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("collect_lkm", ROOT / "scripts/collect-lkm.py")
LKM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LKM)
ANDROID_TARGETS = {
    "aarch64-linux-android": ("arm64-v8a", 183),
    "x86_64-linux-android": ("x86_64", 62),
    "riscv64-linux-android": ("riscv64", 243),
}
INIT_TARGETS = {"aarch64": 183, "x86_64": 62, "riscv64": 243}


def length_prefixed(data, offset=0):
    if offset + 4 > len(data):
        raise ValueError("Truncated APK v2 length prefix")
    size = struct.unpack_from("<I", data, offset)[0]
    end = offset + 4 + size
    if end > len(data):
        raise ValueError("Truncated APK v2 signed data")
    return data[offset + 4:end], end


def apk_certificate(path):
    """Extract the v2 certificate using the same block restrictions as the kernel."""
    data = path.read_bytes()
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0 or eocd + 22 > len(data):
        raise ValueError("APK ZIP end record is missing")
    if eocd + 22 + struct.unpack_from("<H", data, eocd + 20)[0] != len(data):
        raise ValueError("Invalid APK ZIP end record")
    cd_size, cd_offset = struct.unpack_from("<II", data, eocd + 12)
    if cd_offset < 32 or cd_offset + cd_size != eocd:
        raise ValueError("Invalid APK ZIP central directory")
    footer = cd_offset - 24
    if data[footer + 8:cd_offset] != b"APK Sig Block 42":
        raise ValueError("APK lacks the v2 signing block required by the kernel")
    size = struct.unpack_from("<Q", data, footer)[0]
    start = cd_offset - size - 8
    if size < 24 or start < 0 or struct.unpack_from("<Q", data, start)[0] != size:
        raise ValueError("Malformed APK signing block")
    cursor = start + 8
    v2_blocks = []
    while cursor < footer:
        if cursor + 12 > footer:
            raise ValueError("Truncated APK signing block entry")
        pair_size = struct.unpack_from("<Q", data, cursor)[0]
        end = cursor + 8 + pair_size
        if pair_size < 4 or end > footer:
            raise ValueError("Malformed APK signing block entry")
        block_id = struct.unpack_from("<I", data, cursor + 8)[0]
        if block_id == 0x7109871A:
            v2_blocks.append(data[cursor + 12:end])
        elif block_id != 0x42726577:
            raise ValueError(f"Kernel rejects APK signing block id 0x{block_id:08x}")
        cursor = end
    if len(v2_blocks) != 1:
        raise ValueError("APK must contain exactly one v2 signing block")
    signers, end = length_prefixed(v2_blocks[0])
    if end != len(v2_blocks[0]):
        raise ValueError("Unexpected trailing APK v2 data")
    signer, end = length_prefixed(signers)
    if end != len(signers):
        raise ValueError("Release APK must contain exactly one signer")
    signed_data, _ = length_prefixed(signer)
    _, offset = length_prefixed(signed_data)  # Digests precede certificates.
    certificates, _ = length_prefixed(signed_data, offset)
    certificate, _ = length_prefixed(certificates)
    if not 1 <= len(certificate) <= 1024:
        raise ValueError("APK certificate exceeds the kernel verifier limit")
    return certificate


def validate_apk(path, identity):
    LKM.require_file(path)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Release APK contains duplicate ZIP entries")
        if "AndroidManifest.xml" not in names or archive.testzip() is not None:
            raise ValueError("Release APK is missing its manifest or has corrupt ZIP entries")
        for abi, machine in ANDROID_TARGETS.values():
            name = f"lib/{abi}/libksud.so"
            if name not in names:
                raise ValueError(f"Release APK is missing {name}")
            header = archive.read(name)[:64]
            if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H", header, 18)[0] != machine:
                raise ValueError(f"Release APK has the wrong ksud architecture in {name}")
    certificate = apk_certificate(path)
    expected_size = identity["certificate_size"]
    expected_size = int(expected_size, 16 if expected_size.startswith("0x") else 10)
    if len(certificate) != expected_size or hashlib.sha256(certificate).hexdigest() != identity["certificate_sha256"]:
        raise ValueError("Release APK certificate does not match the public kernel build identity")


def add_record(records, path, name=None, **metadata):
    LKM.require_file(path)
    records.append({
        "source": path,
        "filename": name or path.name,
        "size": path.stat().st_size,
        "sha256": LKM.sha256(path),
        **metadata,
    })


def collect(artifacts, output, tag, commit, version_file):
    version = LKM.read_version(version_file)
    if tag != f"v{version['name']}":
        raise ValueError(f"Release tag must match version.properties: v{version['name']}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("An exact 40-character source commit is required")
    records = LKM.inspect_lkm(artifacts, LKM.load_targets())
    manager = artifacts / "manager"
    apks = list(manager.glob("*.apk"))
    if len(apks) != 1:
        raise ValueError(f"Expected exactly one Manager APK, found {len(apks)}")
    identity_path = LKM.require_file(manager / "build-identity.txt")
    identity = LKM.read_properties(identity_path)
    required = {"package", "certificate_sha256", "certificate_size", "temporary_test_key", "commit", "version_name", "version_code"}
    if not required <= identity.keys():
        raise ValueError(f"Incomplete public build identity: {sorted(required - identity.keys())}")
    if identity["temporary_test_key"] != "false":
        raise ValueError("Release publication refuses a temporary CI signing key")
    if identity["package"] != "com.xinglinghu.su" or not re.fullmatch(r"[0-9a-f]{64}", identity["certificate_sha256"]):
        raise ValueError("Invalid release Manager package or certificate hash")
    if identity["commit"] != commit or identity["version_name"] != version["name"] or identity["version_code"] != str(version["code"]):
        raise ValueError("Manager identity does not match the release source commit or version")
    validate_apk(apks[0], identity)
    add_record(records, apks[0], kind="manager")
    add_record(records, identity_path, kind="build_identity")
    for target, (_, machine) in ANDROID_TARGETS.items():
        binary = artifacts / f"ksud-{target}" / "ksud"
        LKM.validate_elf(binary, machine, allowed_types=(2, 3))
        add_record(records, binary, f"ksud-{target}", kind="ksud", elf_machine=machine)
    for arch, machine in INIT_TARGETS.items():
        binary = artifacts / f"ksuinit-{arch}" / "ksuinit"
        LKM.validate_elf(binary, machine, allowed_types=(2, 3))
        add_record(records, binary, f"ksuinit-{arch}", kind="ksuinit", elf_machine=machine)
    LKM.write_collection(records, output, "release-manifest.json", version, {"tag": tag, "commit": commit, "build_identity": identity})
    print(f"Validated {len(records)} release assets for {tag}; output: {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version-file", type=Path, default=ROOT / "version.properties")
    args = parser.parse_args()
    collect(args.artifacts, args.output, args.tag, args.commit, args.version_file)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"Release collection failed: {error}", file=sys.stderr)
        sys.exit(1)
