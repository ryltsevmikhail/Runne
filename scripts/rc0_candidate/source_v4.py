"""SourceCraft embedded-upstream fixture checks for evidence profile v4."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .git_inspection import GitInspectionError, run_repository_git, validate_repository_controls
from .source import FixtureSourceCapture, _blocked

PINNED_OPENCODE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
SOURCECRAFT_ORIGIN = "https://git.sourcecraft.dev/ryltsevmg/gocode.git"
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class FixtureSourceExpectationV4:
    candidate_source_revision: str
    captured_origin_main_revision: str
    raw_tree_oid: str
    upstream_tree_oid: str
    upstream_blob_count: int
    upstream_content_digest: str
    opencode_source_sha: str


@dataclass(frozen=True)
class _Snapshot:
    head: str
    parents: tuple[str, ...]
    tree_oid: str
    origin_urls: tuple[str, ...]
    upstream_tree_oid: str
    upstream_blob_count: int
    upstream_content_digest: str
    gitlink_present: bool
    gitmodules_present: bool
    status: bytes


def _output(repository: Path, *arguments: str, check: bool = True) -> bytes:
    return run_repository_git(repository, *arguments, check=check)


def _tree_entries(repository: Path, revision: str) -> tuple[int, str, bool]:
    raw = _output(repository, "ls-tree", "-r", "-z", revision, "--", "upstream")
    digest = hashlib.sha256()
    entries: list[tuple[bytes, bytes]] = []
    gitlink_present = False
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, separator, path = item.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3 or not path.startswith(b"upstream/"):
            raise GitInspectionError("SOURCE_UPSTREAM_BINDING_MISMATCH", "upstream tree entry is malformed")
        _mode, kind, oid = fields
        if kind == b"commit":
            gitlink_present = True
            continue
        if kind != b"blob" or _GIT_SHA.fullmatch(oid.decode("ascii", "ignore")) is None:
            raise GitInspectionError("SOURCE_UPSTREAM_BINDING_MISMATCH", "upstream entry is not a blob")
        entries.append((path, oid))
    for path, oid in sorted(entries):
        digest.update(path)
        digest.update(hashlib.sha256(_output(repository, "cat-file", "blob", oid.decode())).digest())
    return len(entries), digest.hexdigest(), gitlink_present


def _snapshot(repository: Path) -> _Snapshot:
    validate_repository_controls(repository)
    head = _output(repository, "rev-parse", "HEAD").decode("ascii").strip()
    tree_oid = _output(repository, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    parents = tuple(_output(repository, "show", "-s", "--format=%P", "HEAD").decode("ascii").split())
    origin_urls = tuple(
        value.decode("utf-8")
        for value in _output(repository, "config", "--local", "--no-includes", "--null", "--get-all", "remote.origin.url", check=False).split(b"\0")
        if value
    )
    modules = _output(repository, "ls-tree", "-z", head, "--", ".gitmodules")
    try:
        os.stat(Path(repository) / ".gitmodules", follow_symlinks=False)
        modules_present = True
    except FileNotFoundError:
        modules_present = bool(modules)
    upstream_tree_oid = _output(repository, "rev-parse", f"{head}:upstream").decode("ascii").strip()
    if _output(repository, "cat-file", "-t", upstream_tree_oid).strip() != b"tree":
        raise GitInspectionError("SOURCE_UPSTREAM_BINDING_MISMATCH", "upstream is not a tree")
    count, digest, gitlink_present = _tree_entries(repository, head)
    status = _output(repository, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none")
    validate_repository_controls(repository)
    return _Snapshot(head, parents, tree_oid, origin_urls, upstream_tree_oid, count, digest, gitlink_present, modules_present, status)


def validate_fixture_source_v4(
    repository: Path,
    expected: FixtureSourceExpectationV4,
    mutation_hook: Callable[[str, Path], None] | None = None,
) -> FixtureSourceCapture:
    """Validate the v4 embedded-upstream fixture shape without capture authority."""
    identities = (
        expected.candidate_source_revision, expected.captured_origin_main_revision,
        expected.raw_tree_oid, expected.upstream_tree_oid, expected.opencode_source_sha,
    )
    if any(_GIT_SHA.fullmatch(value) is None for value in identities) or _SHA256.fullmatch(expected.upstream_content_digest) is None:
        return _blocked("SOURCE_IDENTITY_INVALID", "raw identity is not canonical lower-case hex")
    if type(expected.upstream_blob_count) is not int or expected.upstream_blob_count < 1:
        return _blocked("SOURCE_IDENTITY_INVALID", "upstream blob count is not positive")
    try:
        initial = _snapshot(Path(repository))
        if mutation_hook is not None:
            mutation_hook("before-final-recheck", Path(repository))
        final = _snapshot(Path(repository))
    except GitInspectionError as error:
        return _blocked(error.reason, error.diagnostic)
    if initial != final:
        return _blocked("SOURCE_SNAPSHOT_CHANGED", "Git snapshot changed during capture")
    if initial.head != expected.candidate_source_revision or initial.head != expected.captured_origin_main_revision:
        return _blocked("SOURCE_REVISION_MISMATCH", "HEAD/raw/origin revisions differ")
    if len(initial.parents) != 1 or any(_GIT_SHA.fullmatch(parent) is None for parent in initial.parents):
        return _blocked("SOURCE_HISTORY_INVALID", "candidate source must have exactly one parent")
    if initial.origin_urls != (SOURCECRAFT_ORIGIN,):
        return _blocked("SOURCE_REMOTE_IDENTITY_MISMATCH", "origin URL is not canonical SourceCraft HTTPS")
    if initial.gitmodules_present:
        return _blocked("SOURCE_GITMODULES_FORBIDDEN", ".gitmodules must be absent for v4")
    if initial.gitlink_present:
        return _blocked("SOURCE_UPSTREAM_GITLINK_FORBIDDEN", "embedded upstream cannot contain gitlinks")
    if initial.status:
        return _blocked("SOURCE_DIRTY", "tracked or untracked source state is dirty")
    if initial.tree_oid != expected.raw_tree_oid:
        return _blocked("SOURCE_RAW_CURRENT_MISMATCH", "raw and current tree object IDs differ")
    if initial.upstream_tree_oid != expected.upstream_tree_oid:
        return _blocked("SOURCE_UPSTREAM_TREE_MISMATCH", "embedded upstream tree object ID differs")
    if initial.upstream_blob_count != expected.upstream_blob_count or initial.upstream_content_digest != expected.upstream_content_digest:
        return _blocked("SOURCE_UPSTREAM_CONTENT_MISMATCH", "embedded upstream blob binding differs")
    if expected.opencode_source_sha != PINNED_OPENCODE_SHA:
        return _blocked("SOURCE_OPENCODE_PROVENANCE_MISMATCH", "OpenCode provenance SHA is not pinned")
    capture = {
        "remote_url": SOURCECRAFT_ORIGIN,
        "captured_origin_main_revision": expected.captured_origin_main_revision,
        "head_revision": initial.head,
        "raw_tree_oid": expected.raw_tree_oid,
        "current_tree_oid": initial.tree_oid,
        "upstream_tree_oid": initial.upstream_tree_oid,
        "upstream_blob_count": initial.upstream_blob_count,
        "upstream_content_digest": initial.upstream_content_digest,
        "opencode_source_sha": expected.opencode_source_sha,
        "capture_evidence_kind": "RAW_GIT_OBJECTS",
        "tree_clean": True,
    }
    return FixtureSourceCapture("FIXTURE_LOCAL_INPUTS_SATISFIED", capture=capture)
