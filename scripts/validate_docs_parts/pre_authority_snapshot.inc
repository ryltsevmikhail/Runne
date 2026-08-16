"""Immutable candidate-index capture primitives for pre-authority validation."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unicodedata
import posixpath


_FROZEN_BYTES = {
    "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json",
    "docs/schemas/pre-authority-document-delta-v1.schema.json",
    "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V2.json",
    "docs/schemas/pre-authority-document-overlay-v2.schema.json",
    "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V3.json",
    "docs/schemas/pre-authority-document-overlay-v3.schema.json",
    "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V4.json",
    "docs/schemas/pre-authority-document-overlay-v4.schema.json",
    "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V5.json",
    "docs/schemas/pre-authority-document-overlay-v5.schema.json",
    "docs/rc0/document-universe-v1.json", "docs/rc0/governed-scope-v1.json", "docs/rc0/status-claims-v1.json",
}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_path(raw: bytes) -> str:
    try:
        path = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("DOCS_PATH_INVALID") from error
    forbidden = {"\u200e", "\u200f", "\u061c", "\u2066", "\u2067", "\u2068", "\u2069"}
    if (not path or path != unicodedata.normalize("NFC", path) or "\\" in path or ":" in path
            or any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} or char in forbidden for char in path)):
        raise ValueError("DOCS_PATH_INVALID")
    parts = path.split("/")
    if any(part in {"", ".", ".."} or part != part.strip() for part in parts):
        raise ValueError("DOCS_PATH_INVALID")
    return path


def strict_json(raw: bytes, code: str):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(code)
            value[key] = item
        return value
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(code) from error


def git_bytes(repo: Path, args: list[str], index_file: Path | None = None, stdin: bytes | None = None) -> bytes:
    env = os.environ.copy()
    env.pop("GIT_INDEX_FILE", None)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    if index_file is not None:
        env["GIT_INDEX_FILE"] = str(index_file)
    result = subprocess.run(["git", "-C", str(repo), *args], input=stdin, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError("DOCS_GIT_FAILURE")
    return result.stdout


def blob_bytes(repo: Path, oids: list[str]) -> dict[str, bytes]:
    """Read every retained blob from Git's object database in one frozen batch."""
    raw, result = git_bytes(repo, ["cat-file", "--batch"], stdin=("\n".join(oids) + "\n").encode()), {}
    while raw:
        header, raw = raw.split(b"\n", 1)
        oid, kind, size = header.decode("ascii").split()
        length = int(size)
        if kind != "blob" or len(raw) < length + 1:
            raise ValueError("DOCS_INDEX_RECORD_INVALID")
        result[oid], raw = raw[:length], raw[length + 1:]
    if set(result) != set(oids):
        raise ValueError("DOCS_INDEX_RECORD_INVALID")
    return result


def snapshot_symlink_target(entries, path):
    """Resolve one logical path through snapshot-only relative symlinks."""
    seen, current = set(), path
    while True:
        if current in seen or current not in entries:
            raise ValueError("DOCS_LEGACY_SYMLINK_INVALID")
        seen.add(current)
        entry = entries[current]
        if entry.mode == "100644":
            return entry.blob_bytes
        if entry.mode != "120000":
            raise ValueError("DOCS_LEGACY_SYMLINK_INVALID")
        try:
            target = entry.blob_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("DOCS_LEGACY_SYMLINK_INVALID") from error
        if not target or target.startswith("/") or "\\" in target or ":" in target:
            raise ValueError("DOCS_LEGACY_SYMLINK_INVALID")
        current = posixpath.normpath(posixpath.join(posixpath.dirname(current), target))
        if current == "." or current == ".." or current.startswith("../"):
            raise ValueError("DOCS_LEGACY_SYMLINK_INVALID")
        safe_path(current.encode())


@dataclass(frozen=True)
class IndexEntry:
    stage: str
    mode: str
    oid: str
    blob_bytes: bytes


@dataclass(frozen=True)
class CandidateSnapshot:
    repo: Path
    head_oid: str
    entries: dict[str, IndexEntry]

    @classmethod
    def capture(cls, repo: Path, *, index_file: Path | None = None):
        head = git_bytes(repo, ["rev-parse", "HEAD"]).decode("ascii").strip()
        mapping, folded, pending = {}, set(), []
        raw_records = git_bytes(repo, ["ls-files", "--stage", "-z"], index_file).split(b"\0")
        for raw_record in filter(None, raw_records):
            try:
                metadata, raw_path = raw_record.split(b"\t", 1)
                mode, oid, stage = metadata.decode("ascii").split(" ")
            except (UnicodeDecodeError, ValueError) as error:
                raise ValueError("DOCS_INDEX_RECORD_INVALID") from error
            path = safe_path(raw_path)
            if path in mapping or path.casefold() in folded or stage != "0" or oid == "0" * 40:
                raise ValueError("DOCS_INDEX_RECORD_INVALID")
            mapping[path] = IndexEntry(stage, mode, oid, b"")
            if mode != "160000" and (path.endswith((".md", ".markdown")) or path.startswith("docs/schemas/") or path in _FROZEN_BYTES):
                pending.append(oid)
            folded.add(path.casefold())
        blobs = blob_bytes(repo, pending) if pending else {}
        mapping = {path: IndexEntry(entry.stage, entry.mode, entry.oid, blobs.get(entry.oid, b"")) for path, entry in mapping.items()}
        targets = []
        for path, entry in mapping.items():
            if path.endswith((".md", ".markdown")) and entry.mode == "120000":
                try:
                    target = entry.blob_bytes.decode("utf-8")
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
                except UnicodeDecodeError:
                    raise ValueError("DOCS_LEGACY_SYMLINK_INVALID") from None
                if target in mapping and mapping[target].mode == "100644":
                    targets.append(mapping[target].oid)
        target_blobs = blob_bytes(repo, targets) if targets else {}
        mapping = {path: IndexEntry(entry.stage, entry.mode, entry.oid, target_blobs.get(entry.oid, entry.blob_bytes)) for path, entry in mapping.items()}
        return cls(repo, head, mapping)

    def bytes(self, path: str) -> bytes:
        entry = self.entries.get(path)
        if entry is None:
            raise ValueError("DOCS_INDEX_RECORD_INVALID")
        return entry.blob_bytes

    def head_paths(self) -> set[str]:
        records = git_bytes(self.repo, ["ls-tree", "-r", "-z", self.head_oid]).split(b"\0")
        return {safe_path(record.split(b"\t", 1)[1]) for record in filter(None, records)}

    def head_entries(self) -> dict[str, tuple[str, str]]:
        records = git_bytes(self.repo, ["ls-tree", "-r", "-z", self.head_oid]).split(b"\0")
        result = {}
        for record in filter(None, records):
            metadata, raw_path = record.split(b"\t", 1)
            mode, _, oid = metadata.decode("ascii").split(" ")
            result[safe_path(raw_path)] = (mode, oid)
        return result
