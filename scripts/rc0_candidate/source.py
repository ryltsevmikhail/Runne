"""Deterministic local Git source checks without remote capture authority."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import FixtureLocalInputsSummary

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


def _git(repo: Path, *arguments: str, check: bool = True) -> bytes:
    environment = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    result = subprocess.run(
        ["git", "-C", os.fspath(repo), "--no-replace-objects", *arguments],
        check=False,
        capture_output=True,
        env=environment,
        timeout=30,
    )
    if check and result.returncode != 0:
        raise ValueError("local fixture Git inspection failed")
    return result.stdout


def _hex(value: object, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _gitlink(repo: Path) -> str | None:
    raw = _git(repo, "ls-tree", "-z", "HEAD", "--", "upstream/opencode")
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        return None
    metadata, separator, path = raw[:-1].partition(b"\t")
    fields = metadata.split(b" ")
    if separator != b"\t" or path != b"upstream/opencode" or len(fields) != 3:
        return None
    mode, kind, oid = fields
    if mode != b"160000" or kind != b"commit":
        return None
    try:
        return oid.decode("ascii")
    except UnicodeDecodeError:
        return None


def validate_fixture_evidence_commit(
    repository: Path, source_sha: str, evidence_revision: str
) -> tuple[str, ...]:
    """Validate a local fixture commit without assigning seal authority."""
    from .evidence import validate_fixture_evidence_entries

    if _GIT_SHA.fullmatch(source_sha) is None or _GIT_SHA.fullmatch(evidence_revision) is None:
        return ("source and evidence revisions must be lower-case Git SHAs",)
    repository = Path(repository)
    if repository.is_symlink() or not repository.is_dir():
        return ("evidence repository path is unsafe",)
    try:
        head = _git(repository, "rev-parse", "HEAD").decode("ascii").strip()
        parents = _git(repository, "show", "-s", "--format=%P", evidence_revision).decode("ascii").split()
        status = _git(
            repository, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"
        )
        changes = _git(
            repository, "diff-tree", "--no-commit-id", "--name-status", "-r", "--no-renames", "-z", source_sha, evidence_revision
        ).split(b"\0")
    except (ValueError, UnicodeDecodeError):
        return ("local evidence commit identity is unavailable",)
    errors: list[str] = []
    if head != evidence_revision or parents != [source_sha] or status:
        errors.append("evidence commit must be clean HEAD with exactly the source parent")
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
        tree = _git(repository, "ls-tree", "-z", evidence_revision, "--", path)
        metadata, separator, listed_path = tree.removesuffix(b"\0").partition(b"\t")
        fields = metadata.split(b" ")
        if separator != b"\t" or listed_path != raw_path or len(fields) != 3:
            errors.append(f"evidence tree entry is malformed: {path}")
            continue
        mode, kind, _oid = fields
        data = _git(repository, "show", f"{evidence_revision}:{path}")
        entries[name] = {"mode": mode.decode("ascii"), "type": kind.decode("ascii"), "data": data}
    errors.extend(validate_fixture_evidence_entries(source_sha, entries))
    return tuple(errors)


def validate_fixture_source(
    repository: Path, expected: FixtureSourceExpectation
) -> FixtureSourceCapture:
    """Compare fixture-supplied raw identity with a clean local repository."""
    repository = Path(repository)
    if repository.is_symlink() or not repository.is_dir():
        return _blocked("SOURCE_PATH_UNSAFE", "repository must be a real directory")
    try:
        root = Path(_git(repository, "rev-parse", "--show-toplevel").decode().strip())
    except (UnicodeDecodeError, ValueError):
        return _blocked("SOURCE_PATH_UNSAFE", "repository root is unavailable")
    if root.resolve() != repository.resolve():
        return _blocked("SOURCE_PATH_UNSAFE", "repository path is not its Git root")
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
    head = _git(repository, "rev-parse", "HEAD").decode("ascii").strip()
    if head != expected.candidate_source_revision or head != expected.captured_origin_main_revision:
        return _blocked("SOURCE_REVISION_MISMATCH", "HEAD/raw/origin revisions differ")
    parents = _git(repository, "show", "-s", "--format=%P", "HEAD").decode("ascii").split()
    if len(parents) != 1 or not _hex(parents[0], _GIT_SHA):
        return _blocked("SOURCE_HISTORY_INVALID", "candidate source must have exactly one parent")
    status = _git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        return _blocked("SOURCE_DIRTY", "tracked, untracked or submodule state is dirty")
    urls = _git(repository, "config", "--get-all", "remote.origin.url", check=False)
    remote_urls = tuple(line.decode("utf-8") for line in urls.splitlines())
    if len(remote_urls) != 1 or remote_urls[0] not in ALLOWED_ORIGIN_URLS:
        return _blocked("SOURCE_REMOTE_IDENTITY_MISMATCH", "origin URL is not one exact allowed HTTPS identity")
    modules_path = repository / ".gitmodules"
    if modules_path.is_symlink() or not modules_path.is_file():
        return _blocked("SOURCE_GITMODULES_POLICY_MISMATCH", ".gitmodules is absent or unsafe")
    if not isinstance(expected.expected_gitmodules_bytes, bytes):
        return _blocked("SOURCE_GITMODULES_POLICY_MISMATCH", ".gitmodules policy bytes are malformed")
    committed_modules = _git(repository, "show", "HEAD:.gitmodules")
    current_modules = modules_path.read_bytes()
    expected_digest = hashlib.sha256(expected.expected_gitmodules_bytes).hexdigest()
    current_digest = hashlib.sha256(current_modules).hexdigest()
    if (
        expected.expected_gitmodules_bytes != CANONICAL_GITMODULES_BYTES
        or expected.raw_gitmodules_sha256 != expected_digest
        or committed_modules != expected.expected_gitmodules_bytes
        or current_modules != expected.expected_gitmodules_bytes
    ):
        return _blocked("SOURCE_GITMODULES_POLICY_MISMATCH", ".gitmodules bytes or policy digest differ")
    current_tree = _git(repository, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if current_tree != expected.raw_tree_oid:
        return _blocked("SOURCE_RAW_CURRENT_MISMATCH", "raw and current tree object IDs differ")
    current_gitlink = _gitlink(repository)
    if (
        expected.raw_opencode_gitlink_revision != PINNED_OPENCODE_SHA
        or current_gitlink != PINNED_OPENCODE_SHA
    ):
        return _blocked("SOURCE_GITLINK_POLICY_MISMATCH", "OpenCode gitlink is not the pinned revision")
    capture: dict[str, object] = {
        "remote_url": remote_urls[0],
        "captured_origin_main_revision": expected.captured_origin_main_revision,
        "head_revision": head,
        "raw_tree_oid": expected.raw_tree_oid,
        "current_tree_oid": current_tree,
        "raw_gitmodules_sha256": expected.raw_gitmodules_sha256,
        "current_gitmodules_sha256": current_digest,
        "raw_opencode_gitlink_revision": expected.raw_opencode_gitlink_revision,
        "current_opencode_gitlink_revision": current_gitlink,
        "capture_evidence_kind": "RAW_GIT_OBJECTS",
        "tree_clean": True,
    }
    return FixtureSourceCapture("FIXTURE_LOCAL_INPUTS_SATISFIED", capture=capture)


def capture_current_source() -> FixtureLocalInputsSummary:
    """Refuse operational capture until an independent operator authorizes it."""
    return FixtureLocalInputsSummary("BLOCKED", "EXTERNAL_SOURCE_CAPTURE_REQUIRES_APPROVAL")
