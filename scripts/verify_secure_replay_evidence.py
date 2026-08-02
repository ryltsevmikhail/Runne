#!/usr/bin/env python3
"""Verify an immutable Secure Replay evidence snapshot from Git objects."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from typing import Any


ALGORITHM = "git-tree-diff-sha256-v1"
REGULAR_BLOB_MODES = {"100644", "100755"}


def fail(message: str) -> None:
    print(f"secure replay evidence verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def git(repository: pathlib.Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        env=os.environ | {"GIT_NO_REPLACE_OBJECTS": "1"},
    )
    if result.returncode != 0:
        fail("required immutable Git object is unavailable")
    return result.stdout


def full_sha(reference: str) -> bool:
    return len(reference) == 40 and all(char in "0123456789abcdef" for char in reference)


def safe_relative_path(value: Any) -> str:
    if not isinstance(value, str):
        fail("manifest path is not a string")
    path = pathlib.PurePosixPath(value)
    if not path.parts or path.is_absolute() or value != path.as_posix() or ".." in path.parts:
        fail("manifest path is not a safe repository-relative path")
    return path.as_posix()


def repository_for(evidence_path: pathlib.Path) -> pathlib.Path:
    if evidence_path.is_symlink() or not evidence_path.is_file():
        fail("manifest path is not a current regular non-symlink file")
    result = subprocess.run(
        ["git", "-C", str(evidence_path.parent), "rev-parse", "--show-toplevel"],
        capture_output=True,
        env=os.environ | {"GIT_NO_REPLACE_OBJECTS": "1"},
    )
    if result.returncode != 0:
        fail("manifest path is not inside a Git repository")
    return pathlib.Path(result.stdout.decode().strip()).resolve()


def resolve_commit(repository: pathlib.Path, reference: str, label: str) -> str:
    if not full_sha(reference):
        fail(f"{label} must be a full lowercase SHA-1")
    commit = git(repository, "rev-parse", "--verify", f"{reference}^{{commit}}").decode().strip()
    if commit != reference:
        fail(f"{label} does not identify its immutable commit")
    return commit


def parse_diff(data: bytes) -> dict[str, str]:
    fields = data.split(b"\0")
    if fields[-1:] != [b""] or (len(fields) - 1) % 2:
        fail("immutable name-status output is malformed")
    changed: dict[str, str] = {}
    for index in range(0, len(fields) - 1, 2):
        try:
            status, path = fields[index].decode(), fields[index + 1].decode()
        except UnicodeDecodeError:
            fail("immutable changed path is not UTF-8")
        if status not in {"A", "M", "D"} or path in changed:
            fail("immutable name-status output has an unsafe disposition")
        changed[path] = status
    return changed


def parse_tree(data: bytes) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for item in data.split(b"\0"):
        if not item:
            continue
        try:
            metadata, raw_path = item.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            path = raw_path.decode()
        except (UnicodeDecodeError, ValueError):
            fail("immutable tree output is malformed")
        if path in entries:
            fail("immutable tree has duplicate paths")
        entries[path] = (mode, kind, oid)
    return entries


def sha256_blob(repository: pathlib.Path, oid: str) -> str:
    return hashlib.sha256(git(repository, "cat-file", "blob", oid)).hexdigest()


def manifest_entries(record: dict[str, Any]) -> dict[str, tuple[str, str | None]]:
    subject = record.get("subject")
    if not isinstance(subject, dict):
        fail("subject is missing")
    manifest = subject.get("changedFileManifest")
    if not isinstance(manifest, list):
        fail("changed-file manifest is missing")
    expected: dict[str, tuple[str, str | None]] = {}
    for entry in manifest:
        if not isinstance(entry, dict):
            fail("manifest entry is not an object")
        path, status, digest = safe_relative_path(entry.get("path")), entry.get("status"), entry.get("sha256")
        if path in expected:
            fail(f"duplicate manifest path: {path}")
        if status == "present" and isinstance(digest, str) and len(digest) == 64 and all(
            char in "0123456789abcdef" for char in digest
        ):
            expected[path] = (status, digest)
        elif status == "deleted" and digest is None:
            expected[path] = (status, None)
        else:
            fail(f"invalid manifest disposition for: {path}")
    return expected


def verify(evidence_path: pathlib.Path, base_reference: str, head_reference: str) -> None:
    evidence_path = evidence_path.absolute()
    repository = repository_for(evidence_path)
    try:
        relative_evidence = evidence_path.resolve().relative_to(repository).as_posix()
    except ValueError:
        fail("manifest path is outside the repository")
    base_commit = resolve_commit(repository, base_reference, "base")
    head_commit = resolve_commit(repository, head_reference, "head")
    if subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", base_commit, head_commit],
        env=os.environ | {"GIT_NO_REPLACE_OBJECTS": "1"},
    ).returncode != 0:
        fail("source base commit is not an ancestor of source head commit")
    try:
        record = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("manifest is not readable JSON")
    subject = record.get("subject")
    if not isinstance(subject, dict):
        fail("subject is missing")
    if subject.get("sourceBaseCommit") != base_commit:
        fail("manifest source base commit does not match --base")
    if subject.get("sourceHeadCommit") != head_commit:
        fail("manifest source head commit does not match --head")
    if subject.get("manifestAlgorithm") != ALGORITHM:
        fail("manifest algorithm is not immutable snapshot v1")
    if subject.get("manifestSelfExcludedPath") != relative_evidence:
        fail("self-excluded evidence path does not identify this record")
    expected = manifest_entries(record)
    if relative_evidence in expected:
        fail("manifest self-exclusion is not exact")
    actual = parse_diff(git(
        repository, "diff", "--name-status", "-z", "--no-renames", base_commit, head_commit, "--"
    ))
    if relative_evidence not in actual:
        fail("manifest self-excluded path is not changed in the historical snapshot")
    actual.pop(relative_evidence)
    if set(expected) != set(actual):
        details = []
        missing, stale = sorted(set(actual) - set(expected)), sorted(set(expected) - set(actual))
        if missing:
            details.append(f"unlisted changed paths: {', '.join(missing)}")
        if stale:
            details.append(f"stale manifest paths: {', '.join(stale)}")
        fail("; ".join(details))
    tree = parse_tree(git(repository, "ls-tree", "-r", "-z", head_commit))
    evidence_entry = tree.get(relative_evidence)
    if evidence_entry is None or evidence_entry[0] not in REGULAR_BLOB_MODES or evidence_entry[1] != "blob":
        fail("historical manifest path is not a regular blob")
    for path, (status, digest) in expected.items():
        actual_status, tree_entry = actual[path], tree.get(path)
        if status == "deleted":
            if actual_status != "D":
                fail(f"expected deleted path has Git status {actual_status}: {path}")
            if tree_entry is not None:
                fail(f"expected deleted path is present in source head: {path}")
            continue
        if actual_status == "D":
            fail(f"expected present path is deleted: {path}")
        if tree_entry is None or tree_entry[0] not in REGULAR_BLOB_MODES or tree_entry[1] != "blob":
            fail(f"historical manifest path is not a regular blob: {path}")
        if sha256_blob(repository, tree_entry[2]) != digest:
            fail(f"SHA-256 mismatch for: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    arguments = parser.parse_args()
    verify(arguments.manifest, arguments.base, arguments.head)
    print("secure replay evidence manifest verified")


if __name__ == "__main__":
    main()
