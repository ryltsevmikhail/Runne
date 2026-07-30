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


def resolve_commit(repository: pathlib.Path, reference: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "rev-parse",
            "--verify",
            f"{reference}^{{commit}}",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"invalid Git commit reference: {reference}")
    return result.stdout.strip()


def changed_paths(repository: pathlib.Path, base_commit: str) -> dict[str, str]:
    tracked: dict[str, str] = {}
    for line in git(
        repository,
        "diff",
        "--name-status",
        "--no-renames",
        "--diff-filter=ACMRDTUXB",
        base_commit,
        "--",
    ):
        status, path = line.split("\t", 1)
        tracked[path] = status
    untracked = git(
        repository,
        "ls-files",
        "--others",
        "--exclude-standard",
        "--",
        *IMPLEMENTATION_ROOTS,
    )
    return tracked | dict.fromkeys(untracked, "?")


def verify(
    evidence_path: pathlib.Path,
    base_reference: str,
    head_reference: str,
) -> None:
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
    base_commit = resolve_commit(repository, base_reference)
    head_commit = resolve_commit(repository, head_reference)
    current_head = resolve_commit(repository, "HEAD")
    if head_commit != current_head:
        fail("head must resolve to the current checkout HEAD")
    record = json.loads(evidence_path.read_text(encoding="utf-8"))
    subject = record.get("subject")
    if not isinstance(subject, dict):
        fail("subject is missing")
    manifest_base_commit = subject.get("sourceBaseCommit")
    if manifest_base_commit != base_commit:
        fail("manifest source base commit does not match --base")
    if subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            base_commit,
            head_commit,
        ],
        capture_output=True,
    ).returncode != 0:
        fail("source base commit is not an ancestor of --head")
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

    actual = changed_paths(repository, base_commit)
    actual.pop(relative_evidence, None)
    actual_paths = set(actual)
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
            if actual[relative_path] != "D":
                fail(
                    "expected deleted path has Git status "
                    f"{actual[relative_path]}: {relative_path}"
                )
            if path.exists() or path.is_symlink():
                fail(f"expected deleted path exists: {relative_path}")
            continue
        if actual[relative_path] == "D":
            fail(f"expected present path is deleted: {relative_path}")
        if not path.is_file() or path.is_symlink():
            fail(f"manifest path is not a regular file: {relative_path}")
        if sha256(path) != expected_digest:
            fail(f"SHA-256 mismatch for: {relative_path}")


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
