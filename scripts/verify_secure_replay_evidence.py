#!/usr/bin/env python3
"""Verify the exhaustive Secure Replay exact-snapshot changed-file manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any


IMPLEMENTATION_ROOTS = ("apps", "contracts", "crates", "docs", "scripts", "tests")


def git(repository: pathlib.Path, *arguments: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def fail(message: str) -> None:
    print(f"secure replay evidence verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def safe_relative_path(value: Any) -> pathlib.PurePosixPath:
    if not isinstance(value, str):
        fail("manifest path is not a string")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or ".." in path.parts:
        fail("manifest path is not a safe repository-relative path")
    return path


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def changed_paths(repository: pathlib.Path, base_commit: str) -> set[str]:
    tracked = set(
        git(
            repository,
            "diff",
            "--name-only",
            "--no-renames",
            "--diff-filter=ACMRDTUXB",
            base_commit,
            "--",
        )
    )
    untracked = set(
        git(
            repository,
            "ls-files",
            "--others",
            "--exclude-standard",
            "--",
            *IMPLEMENTATION_ROOTS,
        )
    )
    return tracked | untracked


def verify(evidence_path: pathlib.Path) -> None:
    repository = pathlib.Path(
        subprocess.run(
            ["git", "-C", str(evidence_path.parent), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    ).resolve()
    try:
        relative_evidence = evidence_path.resolve().relative_to(repository).as_posix()
    except ValueError:
        fail("evidence path is outside the repository")
    record = json.loads(evidence_path.read_text(encoding="utf-8"))
    subject = record.get("subject")
    if not isinstance(subject, dict):
        fail("subject is missing")
    base_commit = subject.get("sourceBaseCommit")
    if (
        not isinstance(base_commit, str)
        or len(base_commit) != 40
        or any(character not in "0123456789abcdef" for character in base_commit)
    ):
        fail("source base commit is invalid")
    if subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", base_commit, "HEAD"],
        capture_output=True,
    ).returncode != 0:
        fail("source base commit is not an ancestor of HEAD")
    if subject.get("manifestSelfExcludedPath") != relative_evidence:
        fail("self-excluded evidence path does not identify this record")
    manifest = subject.get("changedFileManifest")
    if not isinstance(manifest, list):
        fail("changed-file manifest is missing")

    expected: dict[str, tuple[str, str | None]] = {}
    for entry in manifest:
        if not isinstance(entry, dict):
            fail("manifest entry is not an object")
        path = safe_relative_path(entry.get("path")).as_posix()
        status = entry.get("status")
        digest = entry.get("sha256")
        if path in expected:
            fail(f"duplicate manifest path: {path}")
        if status == "present":
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                fail(f"invalid SHA-256 for: {path}")
            expected[path] = (status, digest)
        elif status == "deleted" and digest is None:
            expected[path] = (status, None)
        else:
            fail(f"invalid manifest disposition for: {path}")

    actual_paths = changed_paths(repository, base_commit)
    actual_paths.discard(relative_evidence)
    if set(expected) != actual_paths:
        missing = sorted(actual_paths - set(expected))
        stale = sorted(set(expected) - actual_paths)
        details = []
        if missing:
            details.append(f"unlisted changed paths: {', '.join(missing)}")
        if stale:
            details.append(f"stale manifest paths: {', '.join(stale)}")
        fail("; ".join(details))

    for relative_path, (status, expected_digest) in expected.items():
        path = repository / relative_path
        if status == "deleted":
            if path.exists():
                fail(f"expected deleted path exists: {relative_path}")
            continue
        if not path.is_file() or path.is_symlink():
            fail(f"manifest path is not a regular file: {relative_path}")
        if sha256(path) != expected_digest:
            fail(f"SHA-256 mismatch for: {relative_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    arguments = parser.parse_args()
    verify(arguments.evidence)
    print("secure replay evidence manifest verified")


if __name__ == "__main__":
    main()
