#!/usr/bin/env python3
"""Verify the recorded Local Engine import inventory and byte digest."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/03-subsystems/local-engine/IMPORT_MANIFEST.json"


def embedded_paths(root: Path) -> list[str]:
    raw = subprocess.check_output(
        ["git", "ls-files", "-z", "local-engine"], cwd=root
    )
    return sorted(item.decode() for item in raw.split(b"\0") if item)


def embedded_digest(root: Path, paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        mode = b"100755" if path.stat().st_mode & 0o111 else b"100644"
        digest.update(relative.removeprefix("local-engine/").encode())
        digest.update(b"\0")
        digest.update(mode)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    paths = embedded_paths(ROOT)
    if manifest.get("schema") != "runne-local-engine-import.v1":
        return 2
    if len(paths) != manifest.get("embedded_file_count"):
        return 2
    if embedded_digest(ROOT, paths) != manifest.get("embedded_tree_sha256"):
        return 2
    print(
        "Local Engine import verified:",
        manifest["upstream_commit"],
        manifest["embedded_tree_sha256"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
