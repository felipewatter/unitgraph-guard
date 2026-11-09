"""Build deterministic, bounded, offline source archives and SHA-256 manifests."""
from __future__ import annotations

import hashlib
import json
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE_DIRS = ("src", "tests", "examples", "docs", "scripts", ".github")
INCLUDE_FILES = {".gitignore", "pyproject.toml", "README.md", "README.en.md", "CHANGELOG.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"}
OMIT = {".git", ".pytest_cache", ".coverage", "__pycache__", "dist", "build", ".tox", ".venv", "venv", ".ruff_cache"}
FIXED_TIME = (2026, 11, 9, 0, 0, 0)


def is_source(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    parts = relative.parts
    return (path.is_file() and not path.is_symlink() and
            all(p not in OMIT and not p.endswith(".egg-info") and not p.endswith(".pyc") for p in parts) and
            (parts[0] in INCLUDE_DIRS or str(relative) in INCLUDE_FILES))


def build(destination: Path) -> tuple[Path, Path, Path]:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    prefix = f"unitgraph-guard-v{version}"
    destination.mkdir(parents=True, exist_ok=True)
    paths = sorted((p for p in ROOT.rglob("*") if is_source(p)), key=lambda p: p.relative_to(ROOT).as_posix())
    if len(paths) < 20 or not any(p.name == "README.md" for p in paths):
        raise ValueError("release would be incomplete")
    manifest = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    archive = destination / f"{prefix}-source.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in paths:
            info = zipfile.ZipInfo(prefix + "/" + path.relative_to(ROOT).as_posix(), date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    manifest_path = destination / f"{prefix}-manifest.json"
    manifest_path.write_text(json.dumps({"schemaVersion": 1, "version": version, "sha256": manifest}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    checksums = destination / f"{prefix}-SHA256SUMS.txt"
    assets = [archive, manifest_path] + sorted(destination.glob(f"unitgraph_guard-{version}-*.whl"))
    checksums.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in assets), encoding="utf-8")
    return archive, manifest_path, checksums


if __name__ == "__main__":
    for path in build(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist"):
        print(path)
