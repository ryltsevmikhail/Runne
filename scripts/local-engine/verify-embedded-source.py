#!/usr/bin/env python3
"""Fail closed when the embedded Local Engine provenance drifts."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/03-subsystems/local-engine/IMPORT_MANIFEST.json"


def embedded_paths(root: Path) -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z", "local-engine"], cwd=root)
    return sorted(item.decode() for item in raw.split(b"\0") if item)


def read_regular_file(path: Path) -> bytes:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"path is not a regular file: {path}")
    return path.read_bytes()


def read_json_file(path: Path) -> dict:
    return json.loads(read_regular_file(path).decode("utf-8"))


def file_mode(path: Path) -> str:
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError(f"path is not a regular file: {path}")
    return "100755" if mode & 0o111 else "100644"


def embedded_digest(root: Path, paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        digest.update(relative.removeprefix("local-engine/").encode())
        digest.update(b"\0")
        digest.update(file_mode(path).encode())
        digest.update(b"\0")
        digest.update(read_regular_file(path))
        digest.update(b"\0")
    return digest.hexdigest()


def inventory_digest(files: list[dict[str, str]]) -> str:
    digest = hashlib.sha256()
    for entry in files:
        digest.update(entry["path"].encode())
        digest.update(b"\0")
        digest.update(entry["mode"].encode())
        digest.update(b"\0")
        digest.update(entry["sha256"].encode())
        digest.update(b"\0")
    return digest.hexdigest()


def upstream_files(manifest: dict) -> dict[str, tuple[str, str]]:
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("upstream file inventory is missing")
    normalized: list[dict[str, str]] = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "mode", "sha256"}:
            raise ValueError("upstream file inventory entry is invalid")
        path, mode, sha256 = entry["path"], entry["mode"], entry["sha256"]
        if not all(isinstance(value, str) for value in (path, mode, sha256)):
            raise ValueError("upstream file inventory value is invalid")
        if path.startswith("/") or ".." in Path(path).parts:
            raise ValueError("upstream file inventory path is unsafe")
        if mode not in {"100644", "100755"} or len(sha256) != 64:
            raise ValueError("upstream file inventory metadata is invalid")
        int(sha256, 16)
        normalized.append(entry)
    if normalized != sorted(normalized, key=lambda entry: entry["path"]):
        raise ValueError("upstream file inventory is not sorted")
    if len({entry["path"] for entry in normalized}) != len(normalized):
        raise ValueError("upstream file inventory has duplicate paths")
    if manifest.get("file_count") != len(normalized):
        raise ValueError("upstream file count does not match")
    if manifest.get("tree_sha256") != inventory_digest(normalized):
        raise ValueError("upstream tree digest does not match")
    return {entry["path"]: (entry["mode"], entry["sha256"]) for entry in normalized}


def classifications(root: Path, upstream: dict[str, tuple[str, str]]) -> dict[str, list[str]]:
    current = {path.removeprefix("local-engine/") for path in embedded_paths(root)}
    modified = []
    for path, expected in upstream.items():
        if path in current:
            target = root / "local-engine" / path
            actual = (file_mode(target), hashlib.sha256(read_regular_file(target)).hexdigest())
            if actual != expected:
                modified.append(path)
    return {
        "modified_after_import": sorted(modified),
        "added_after_import": sorted(current - set(upstream)),
        "missing_after_import": sorted(set(upstream) - current),
    }


def verify(root: Path, manifest_path: Path) -> dict:
    manifest = read_json_file(manifest_path)
    if manifest.get("schema") != "runne-local-engine-import.v2":
        raise ValueError("unexpected import manifest schema")
    upstream_name = manifest.get("upstream_tree_manifest")
    if not isinstance(upstream_name, str) or Path(upstream_name).name != upstream_name:
        raise ValueError("upstream tree manifest path is invalid")
    upstream_manifest = read_json_file(manifest_path.parent / upstream_name)
    if upstream_manifest.get("schema") != "runne-local-engine-upstream-tree.v1":
        raise ValueError("unexpected upstream tree manifest schema")
    upstream = upstream_files(upstream_manifest)
    for field in ("upstream_repository", "upstream_commit"):
        if manifest.get(field) != upstream_manifest.get(field):
            raise ValueError(f"{field} does not match upstream tree manifest")
    if manifest.get("upstream_file_count") != len(upstream):
        raise ValueError("recorded upstream file count does not match")
    if manifest.get("upstream_tree_sha256") != upstream_manifest.get("tree_sha256"):
        raise ValueError("recorded upstream tree digest does not match")
    paths = embedded_paths(root)
    if manifest.get("embedded_file_count") != len(paths):
        raise ValueError("embedded file count does not match")
    if manifest.get("embedded_tree_sha256") != embedded_digest(root, paths):
        raise ValueError("embedded tree digest does not match")
    actual = classifications(root, upstream)
    if any(manifest.get(key) != value for key, value in actual.items()):
        raise ValueError("import classifications do not match")
    return manifest


def main() -> int:
    try:
        manifest = verify(ROOT, MANIFEST)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
        return 2
    print("Local Engine import verified:", manifest["upstream_commit"], manifest["embedded_tree_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
