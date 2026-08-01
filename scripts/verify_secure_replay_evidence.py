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


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


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


def changed_paths(
    repository: pathlib.Path, base_commit: str, head_commit: str
) -> dict[str, str]:
    tracked: dict[str, str] = {}
    for line in git(
        repository,
        "diff",
        "--name-status",
        "--no-renames",
        "--diff-filter=ACMRDTUXB",
        base_commit,
        head_commit,
        "--",
    ):
        status, path = line.split("\t", 1)
        tracked[path] = status
    return tracked


def recorded_file_sha256(
    repository: pathlib.Path, head_commit: str, relative_path: str
) -> str:
    tree_entries = git(repository, "ls-tree", head_commit, "--", relative_path)
    if len(tree_entries) != 1:
        fail(f"recorded manifest path is not a regular file: {relative_path}")
    mode, object_type, object_id = tree_entries[0].split("\t", 1)[0].split()
    if mode not in ("100644", "100755") or object_type != "blob":
        fail(f"recorded manifest path is not a regular file: {relative_path}")
    result = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "blob", object_id],
        check=True,
        capture_output=True,
    )
    return sha256(result.stdout)


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
    record = json.loads(evidence_path.read_text(encoding="utf-8"))
    subject = record.get("subject")
    if not isinstance(subject, dict):
        fail("subject is missing")
    manifest_base_commit = subject.get("sourceBaseCommit")
    if manifest_base_commit != base_commit:
        fail("manifest source base commit does not match --base")
    if subject.get("sourceHeadCommit") != head_commit:
        fail("manifest source head commit does not match --head")
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
    if subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            head_commit,
            current_head,
        ],
        capture_output=True,
    ).returncode != 0:
        fail("recorded --head is not an ancestor of the current checkout HEAD")
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

    actual = changed_paths(repository, base_commit, head_commit)
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
        if status == "deleted":
            if actual[relative_path] != "D":
                fail(
                    "expected deleted path has Git status "
                    f"{actual[relative_path]}: {relative_path}"
                )
            continue
        if actual[relative_path] == "D":
            fail(f"expected present path is deleted: {relative_path}")
        if recorded_file_sha256(repository, head_commit, relative_path) != expected_digest:
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
