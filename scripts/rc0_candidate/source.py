"""Deterministic local Git source checks without remote capture authority."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import FixtureLocalInputsSummary
from .git_evidence_snapshot import capture_evidence_commit_snapshot
from .git_inspection import (
    GitInspectionError,
    capture_source_snapshot,
)

PINNED_OPENCODE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
ALLOWED_ORIGIN_URLS = frozenset(
    ("https://github.com/Ryltsevmg/gocode", "https://github.com/Ryltsevmg/gocode.git")
)
CANONICAL_GITMODULES_BYTES = (
    b'[submodule "upstream/opencode"]\n'
    b"\tpath = upstream/opencode\n"
    b"\turl = https://github.com/anomalyco/opencode\n"
)
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class FixtureSourceExpectation:
    candidate_source_revision: str
    captured_origin_main_revision: str
    raw_tree_oid: str
    raw_gitmodules_sha256: str
    raw_opencode_gitlink_revision: str
    expected_gitmodules_bytes: bytes


@dataclass(frozen=True)
class FixtureSourceCapture:
    status: str
    blocked_reason: str | None = None
    capture: dict[str, object] | None = None
    diagnostics: tuple[str, ...] = ()


def _blocked(reason: str, diagnostic: str) -> FixtureSourceCapture:
    return FixtureSourceCapture("BLOCKED", reason, diagnostics=(diagnostic,))


def _hex(value: object, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_fixture_evidence_commit(
    repository: Path, source_sha: str, evidence_revision: str,
    mutation_hook: Callable[[str, Path], None] | None = None,
) -> tuple[str, ...]:
    """Validate a local fixture commit without assigning seal authority."""
    from .evidence import validate_fixture_evidence_entries

    if _GIT_SHA.fullmatch(source_sha) is None or _GIT_SHA.fullmatch(evidence_revision) is None:
        return ("source and evidence revisions must be lower-case Git SHAs",)
    try:
        snapshot = capture_evidence_commit_snapshot(
            Path(repository), source_sha, evidence_revision, mutation_hook
        )
    except (GitInspectionError, UnicodeDecodeError):
        return ("local evidence commit snapshot changed or is unavailable",)
    errors: list[str] = []
    if snapshot.head != evidence_revision or snapshot.parents != (source_sha,) or snapshot.status:
        errors.append("evidence commit must be clean HEAD with exactly the source parent")
    changes = snapshot.changes.split(b"\0")
    if changes and changes[-1] == b"":
        changes.pop()
    if len(changes) % 2:
        return (*errors, "evidence diff is malformed")
    prefix = f"docs/evidence/rc0-candidates/{source_sha}/"
    entries: dict[str, dict[str, object]] = {}
    for index in range(0, len(changes), 2):
        raw_status, raw_path = changes[index : index + 2]
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            errors.append("evidence diff path is not UTF-8")
            continue
        if raw_status != b"A" or not path.startswith(prefix):
            errors.append(f"evidence diff contains a non-evidence source change: {path}")
            continue
        name = path.removeprefix(prefix)
        tree, data = snapshot.tree_results.get(raw_path, (b"", None))
        metadata, separator, listed_path = tree.removesuffix(b"\0").partition(b"\t")
        fields = metadata.split(b" ")
        if separator != b"\t" or listed_path != raw_path or len(fields) != 3:
            errors.append(f"evidence tree entry is malformed: {path}")
            continue
        mode, kind, _oid = fields
        if data is None:
            errors.append(f"evidence tree blob is unavailable: {path}")
            continue
        entries[name] = {"mode": mode.decode("ascii"), "type": kind.decode("ascii"), "data": data}
    errors.extend(validate_fixture_evidence_entries(source_sha, entries))
    return tuple(errors)


def validate_fixture_source(
    repository: Path,
    expected: FixtureSourceExpectation,
    mutation_hook: Callable[[str, Path], None] | None = None,
) -> FixtureSourceCapture:
    """Compare fixture-supplied raw identity with a clean local repository."""
    identities = (
        expected.candidate_source_revision,
        expected.captured_origin_main_revision,
        expected.raw_tree_oid,
        expected.raw_opencode_gitlink_revision,
    )
    if any(not _hex(value, _GIT_SHA) for value in identities) or not _hex(
        expected.raw_gitmodules_sha256, _SHA256
    ):
        return _blocked("SOURCE_IDENTITY_INVALID", "raw identity is not canonical lower-case hex")
    if not isinstance(expected.expected_gitmodules_bytes, bytes):
        return _blocked("SOURCE_GITMODULES_POLICY_MISMATCH", ".gitmodules policy bytes are malformed")
    try:
        snapshot = capture_source_snapshot(Path(repository), mutation_hook)
    except GitInspectionError as error:
        return _blocked(error.reason, error.diagnostic)
    if snapshot.head != expected.candidate_source_revision or snapshot.head != expected.captured_origin_main_revision:
        return _blocked("SOURCE_REVISION_MISMATCH", "HEAD/raw/origin revisions differ")
    if len(snapshot.parents) != 1 or not _hex(snapshot.parents[0], _GIT_SHA):
        return _blocked("SOURCE_HISTORY_INVALID", "candidate source must have exactly one parent")
    if len(snapshot.origin_urls) != 1 or snapshot.origin_urls[0] not in ALLOWED_ORIGIN_URLS:
        return _blocked("SOURCE_REMOTE_IDENTITY_MISMATCH", "origin URL is not one exact allowed HTTPS identity")
    expected_digest = hashlib.sha256(expected.expected_gitmodules_bytes).hexdigest()
    if (
        expected.expected_gitmodules_bytes != CANONICAL_GITMODULES_BYTES
        or expected.raw_gitmodules_sha256 != expected_digest
        or snapshot.gitmodules_bytes != expected.expected_gitmodules_bytes
        or snapshot.gitmodules_sha256 != expected.raw_gitmodules_sha256
    ):
        return _blocked("SOURCE_GITMODULES_POLICY_MISMATCH", ".gitmodules bytes or policy digest differ")
    if snapshot.tree_oid != expected.raw_tree_oid:
        return _blocked("SOURCE_RAW_CURRENT_MISMATCH", "raw and current tree object IDs differ")
    if (
        expected.raw_opencode_gitlink_revision != PINNED_OPENCODE_SHA
        or snapshot.gitlink_oid != PINNED_OPENCODE_SHA
    ):
        return _blocked("SOURCE_GITLINK_POLICY_MISMATCH", "OpenCode gitlink is not the pinned revision")
    capture: dict[str, object] = {
        "remote_url": snapshot.origin_urls[0],
        "captured_origin_main_revision": expected.captured_origin_main_revision,
        "head_revision": snapshot.head,
        "raw_tree_oid": expected.raw_tree_oid,
        "current_tree_oid": snapshot.tree_oid,
        "raw_gitmodules_sha256": expected.raw_gitmodules_sha256,
        "current_gitmodules_sha256": snapshot.gitmodules_sha256,
        "raw_opencode_gitlink_revision": expected.raw_opencode_gitlink_revision,
        "current_opencode_gitlink_revision": snapshot.gitlink_oid,
        "capture_evidence_kind": "RAW_GIT_OBJECTS",
        "tree_clean": True,
    }
    return FixtureSourceCapture("FIXTURE_LOCAL_INPUTS_SATISFIED", capture=capture)


def capture_current_source() -> FixtureLocalInputsSummary:
    """Refuse operational capture until an independent operator authorizes it."""
    return FixtureLocalInputsSummary("BLOCKED", "EXTERNAL_SOURCE_CAPTURE_REQUIRES_APPROVAL")


from .source_v4 import FixtureSourceExpectationV4, validate_fixture_source_v4
