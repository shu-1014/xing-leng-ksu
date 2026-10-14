"""Create an upload-ready source archive without local signing or build files."""
from pathlib import Path
from datetime import date
import os
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "dist" / f"xinglinghu-source-{date.today():%Y%m%d}.zip"
EXCLUDED_DIRECTORIES = {
    ".git", ".gradle", ".idea", ".cxx", ".kotlin", "target", "dist",
    "build", "node_modules", "__pycache__", "private-signing", "captures",
}
EXCLUDED_NAMES = {"local.properties", ".DS_Store", "repack-config.json", "ksuinit"}
EXCLUDED_SUFFIXES = {".apk", ".jks", ".keystore", ".pdb", ".o", ".so", ".ko", ".pyc"}


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    return not (
        any(part in EXCLUDED_DIRECTORIES for part in relative.parts[:-1])
        or path.name in EXCLUDED_NAMES
        or path.suffix.lower() in EXCLUDED_SUFFIXES
        or relative.as_posix() == ".cargo/config.toml"
    )


def main() -> None:
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(DESTINATION, "w", ZIP_DEFLATED) as archive:
        for folder, directories, files in os.walk(ROOT):
            directories[:] = sorted(name for name in directories if name not in EXCLUDED_DIRECTORIES)
            for name in sorted(files):
                path = Path(folder) / name
                if included(path):
                    archive.write(path, "xinglinghu/" + path.relative_to(ROOT).as_posix())
    with ZipFile(DESTINATION) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        assert "xinglinghu/.github/workflows/build-manager.yml" in names
        assert "xinglinghu/uapi/ksu.h" in names
        assert "xinglinghu/manager/app/src/main/AndroidManifest.xml" in names
        assert not any("private-signing/" in name or name.endswith(".jks") for name in names)
    print(f"Created {DESTINATION} ({DESTINATION.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
