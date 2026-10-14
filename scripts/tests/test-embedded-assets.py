"""Exercise release rejection with a complete ELF matrix and broken inputs."""

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_assets", ROOT / "scripts/verify-embedded-assets.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def elf(machine, kind=1, kmi="android14-6.1", module_name="kernelsu", release=None):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, kind, machine, 1)
    struct.pack_into("<Q", header, 40, 64)
    struct.pack_into("<H", header, 52, 64)
    struct.pack_into("<HHH", header, 58, 64, 3, 1)
    android, kernel = kmi.split("-", 1)
    names = b"\0.shstrtab\0.modinfo\0"
    release = release or f"{kernel}.123-{android}"
    info = f"vermagic={release} SMP preempt mod_unload\0name={module_name}\0".encode()
    sections = bytes(64)
    sections += struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 256, len(names), 0, 0, 1, 0)
    sections += struct.pack("<IIQQQQIIQQ", 11, 1, 0, 0, 256 + len(names), len(info), 0, 0, 1, 0)
    return bytes(header) + sections + names + info


class ReleaseAssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "aarch64"
        self.directory.mkdir()
        (self.directory / "ksuinit").write_bytes(elf(183, 2))
        for kmi in VERIFY.collector.load_targets()["kmis"]:
            (self.directory / f"{kmi}_kernelsu.ko").write_bytes(elf(183, kmi=kmi))
        self.module = self.directory / "android14-6.1_kernelsu.ko"

    def test_upstream_version_remains_supported(self):
        properties = self.root / "version.properties"
        properties.write_text("KSU_VERSION_NAME=3.3.1\nKSU_VERSION_CODE=32680\n")
        self.assertEqual(VERIFY.collector.read_version(properties), {"name": "3.3.1", "code": 32680})

    def test_fork_revision_version_is_supported(self):
        properties = self.root / "version.properties"
        properties.write_text("KSU_VERSION_NAME=3.3.1-xinglinghu.1\nKSU_VERSION_CODE=32681\n")
        self.assertEqual(VERIFY.collector.read_version(properties), {"name": "3.3.1-xinglinghu.1", "code": 32681})

    def test_unsafe_or_incomplete_versions_are_rejected(self):
        properties = self.root / "version.properties"
        for version in ["3.3", "3.3.1/../outside", "3.3.1-", "3.3.1--r1", "3.3.1-r 1", "3.3.1-$(id)", "3.3.1-r\\1", "3.3.1-r:1"]:
            with self.subTest(version=version):
                properties.write_text(f"KSU_VERSION_NAME={version}\nKSU_VERSION_CODE=32681\n")
                with self.assertRaisesRegex(ValueError, "safe revision suffix"):
                    VERIFY.collector.read_version(properties)

    def test_complete_matrix_accepts_target_triple(self):
        self.assertEqual(len(VERIFY.verify(self.root, "aarch64-linux-android")["assets"]), 9)

    def test_missing_target_module_rejected(self):
        self.module.unlink()
        with self.assertRaisesRegex(ValueError, "Incomplete KMI matrix"):
            VERIFY.verify(self.root, "aarch64")

    def test_ddk_vermagic_without_android_suffix(self):
        self.module.write_bytes(elf(183, release="6.1.166-dirty"))
        self.assertEqual(len(VERIFY.verify(self.root, "aarch64")["assets"]), 9)

    def test_wrong_architecture_rejected(self):
        self.module.write_bytes(elf(62))
        with self.assertRaisesRegex(ValueError, "Wrong ELF architecture"):
            VERIFY.verify(self.root, "aarch64")

    def test_wrong_kmi_rejected(self):
        self.module.write_bytes(elf(183, kmi="android15-6.6"))
        with self.assertRaisesRegex(ValueError, "KMI/vermagic mismatch"):
            VERIFY.verify(self.root, "aarch64")

    def test_wrong_module_name_rejected(self):
        self.module.write_bytes(elf(183, module_name="other"))
        with self.assertRaisesRegex(ValueError, "Incorrect kernel module name"):
            VERIFY.verify(self.root, "aarch64")

    def test_init_must_be_executable(self):
        (self.directory / "ksuinit").write_bytes(elf(183))
        with self.assertRaisesRegex(ValueError, "Wrong ELF architecture, type"):
            VERIFY.verify(self.root, "aarch64")

    def test_riscv_init_without_unsupported_modules(self):
        directory = self.root / "riscv64"
        directory.mkdir()
        (directory / "ksuinit").write_bytes(elf(243, 2))
        self.assertEqual(len(VERIFY.verify(self.root, "riscv64")["assets"]), 1)


if __name__ == "__main__":
    unittest.main()
