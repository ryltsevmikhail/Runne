#!/usr/bin/env python3
"""Verify explicit evidence-pin successors across Git lineages."""

from __future__ import annotations

from dataclasses import dataclass
import re
import subprocess

from pin_lineage_manifest import require_manifest_fields


FULL = "full"
NON_DOCS = "non_docs"
_GIT_ENV = {"PATH": "/usr/bin:/bin", "GIT_NO_REPLACE_OBJECTS": "1"}
_SHA = re.compile(r"[0-9a-f]{40}")
_SCOPES = {FULL: "_successor", NON_DOCS: "_successor_code"}
REPO_INFRA_EXCLUDED = {
    b"AGENTS.md",
    b".gitmodules",
    b"upstream/README.md",
    b"upstream/opencode",
}


@dataclass(frozen=True, order=True)
class Delta:
    """One Git raw object delta."""

    src_mode: bytes
    dst_mode: bytes
    src_sha: bytes
    dst_sha: bytes
    status: bytes
    path: bytes


def run_git(*arguments: str | bytes) -> subprocess.CompletedProcess[bytes]:
    """Run Git without inheriting caller-controlled repository settings."""
    return subprocess.run(
        ["git", *arguments], capture_output=True, check=False, env=_GIT_ENV
    )


def require_ancestor(commit: str) -> bool:
    """Return whether commit reaches HEAD; reject Git operational failures."""
    result = run_git("merge-base", "--is-ancestor", commit, "HEAD")
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise SystemExit(f"git merge-base failed with exit {result.returncode}")


def _require_git(*arguments: str | bytes) -> bytes:
    result = run_git(*arguments)
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(map(str, arguments))} failed with exit {result.returncode}")
    return result.stdout


def _require_commit(commit: str) -> None:
    _require_git("cat-file", "-e", commit + "^{commit}")


def _raw_deltas(commit: str) -> tuple[Delta, ...]:
    raw = _require_git(
        "diff-tree", "-r", "--raw", "-z", "--no-abbrev", "--no-renames", commit + "^", commit
    )
    records = raw.split(b"\0")
    if records[-1:] != [b""]:
        raise SystemExit("git diff-tree raw output is malformed")
    deltas: list[Delta] = []
    for index in range(0, len(records) - 1, 2):
        header, path = records[index:index + 2]
        fields = header.split()
        if len(fields) != 5 or not header.startswith(b":") or not path:
            raise SystemExit("git diff-tree raw record is malformed")
        src_mode, dst_mode, src_sha, dst_sha, status = fields
        deltas.append(Delta(src_mode[1:], dst_mode, src_sha, dst_sha, status, path))
    return tuple(sorted(deltas))


def _non_docs_tree_state(commit: str) -> dict[bytes, tuple[bytes, bytes, bytes]]:
    raw = _require_git("ls-tree", "-r", "-z", commit)
    state: dict[bytes, tuple[bytes, bytes, bytes]] = {}
    records = raw.split(b"\0")
    if records[-1:] != [b""]:
        raise SystemExit("git ls-tree output is malformed")
    for record in records[:-1]:
        header, separator, path = record.partition(b"\t")
        fields = header.split()
        if separator != b"\t" or len(fields) != 3 or not path:
            raise SystemExit("git ls-tree record is malformed")
        mode, kind, oid = fields
        if (
            re.fullmatch(rb"[0-7]{6}", mode) is None
            or kind not in (b"blob", b"commit")
            or re.fullmatch(rb"[0-9a-f]{40}", oid) is None
        ):
            raise SystemExit("git ls-tree record is not a supported object")
        if not path.startswith(b"docs/"):
            if path in state:
                raise SystemExit("git ls-tree contains a duplicate path")
            state[path] = (mode, kind, oid)
    return state


def require_matching_tree_state(commit: str, successor: str) -> None:
    """Require equal complete non-docs path-to-object state."""
    expected = _non_docs_tree_state(commit)
    actual = _non_docs_tree_state(successor)
    for path in REPO_INFRA_EXCLUDED:
        expected.pop(path, None)
        actual.pop(path, None)
    if expected != actual:
        raise SystemExit("non-docs tree state differs")


def require_lineage(evidence: str, field: str, *, scope: str) -> str:
    """Resolve a field through the caller-owned permitted successor scope."""
    if scope not in _SCOPES:
        raise ValueError(f"unknown lineage scope: {scope}")
    related = (field, field + "_successor", field + "_successor_code")
    manifest = require_manifest_fields(evidence, related)
    suffix = _SCOPES[scope]
    forbidden = set(related[1:]) - {field + suffix}
    present_forbidden = sorted(forbidden & manifest.keys())
    if present_forbidden:
        raise SystemExit(f"evidence has disallowed successor scope: {present_forbidden[0]}")
    commit = manifest.get(field)
    if commit is None or _SHA.fullmatch(commit) is None:
        raise SystemExit(f"evidence field is missing or invalid: {field}")
    _require_commit(commit)
    if require_ancestor(commit):
        return commit
    successor = manifest.get(field + suffix)
    if successor is None or _SHA.fullmatch(successor) is None:
        raise SystemExit(f"{field} does not reach HEAD and has no permitted successor")
    _require_commit(successor)
    if not require_ancestor(successor):
        raise SystemExit(f"{field}{suffix} does not reach HEAD")
    expected = _raw_deltas(commit)
    actual = _raw_deltas(successor)
    if scope == NON_DOCS:
        expected = tuple(delta for delta in expected if not delta.path.startswith(b"docs/"))
        actual = tuple(delta for delta in actual if not delta.path.startswith(b"docs/"))
    if expected != actual:
        raise SystemExit(f"{field}{suffix} is not {scope}-patch identical to {field}")
    if scope == NON_DOCS:
        require_matching_tree_state(commit, successor)
    return successor
