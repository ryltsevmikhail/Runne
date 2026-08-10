"""Strict local I/O and Git source identity helpers."""

import hashlib
import json
import subprocess
from pathlib import Path


def load_json(path: Path) -> object:
    """Read JSON and reject duplicate object keys at every nesting level."""

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def has_raw_sha256(raw: bytes, sidecar: str) -> bool:
    """Match the repository's exact raw-byte SHA-256 sidecar convention."""

    return sidecar == f"sha256:{hashlib.sha256(raw).hexdigest()}\n"


def registry_ids(path: Path, prefix: str) -> set[str]:
    """Extract canonical table IDs without treating arbitrary prose as an ID registry."""

    return {
        line.split("|", 2)[1].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("| ") and line.split("|", 2)[1].strip().startswith(prefix)
    }


def git_output(root: Path, *args: str) -> bytes:
    return subprocess.run(("git", "-C", str(root), *args), check=True, capture_output=True).stdout


def clean_source_paths(root: Path) -> bool:
    """Evidence-only changes cannot alter the candidate source identity."""

    output = git_output(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    paths = [item[3:].decode("utf-8", "surrogateescape") for item in output.split(b"\0") if item]
    return all(path.startswith("docs/evidence/") for path in paths)


def canonical_source_content_digest(root: Path, source_ref: str) -> str:
    """Hash sorted Git blobs, excluding only immutable evidence records."""

    entries = git_output(root, "ls-tree", "-r", "-z", source_ref).split(b"\0")
    digest = hashlib.sha256()
    for entry in entries:
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, kind, _object_id = metadata.split(b" ", 2)
        if kind != b"blob" or path.startswith(b"docs/evidence/"):
            continue
        content = git_output(root, "show", f"{source_ref}:{path.decode('utf-8', 'surrogateescape')}")
        content_digest = hashlib.sha256(content).digest()
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(len(mode).to_bytes(2, "big"))
        digest.update(mode)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content_digest)
    return digest.hexdigest()
