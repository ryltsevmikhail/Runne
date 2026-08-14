"""Isolated Git-index fixtures for platform claim migration tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from contextlib import AbstractContextManager
from pathlib import Path

from scripts.rc0_policy.canonical import canonical_bytes


ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "scripts/rc0_policy/fixtures/platform_claim_migration/v1/valid"
TASK3_VALID = ROOT / "scripts/rc0_policy/fixtures/platform_scope/v1/valid"


class TemporaryIndexFixture(AbstractContextManager["TemporaryIndexFixture"]):
    def __init__(self, documents: dict[str, str] | None = None) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self._outside = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        self.index = self.root / ".git/index"
        self._documents = _documents() if documents is None else documents

    def __enter__(self) -> "TemporaryIndexFixture":
        for path, body in self._documents.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        _run(self.root, "init", "--quiet")
        _run(self.root, "add", "docs")
        return self

    def __exit__(self, *unused: object) -> None:
        self._outside.cleanup()
        self._directory.cleanup()

    def add_markdown(self, path: str, body: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        _run(self.root, "add", path)
        _run(self.root, "write-tree")

    def unstaged_swap(self, path: str, body: str) -> None:
        (self.root / path).write_text(body, encoding="utf-8")

    def external_leaf_symlink(self, path: str) -> None:
        target = self.root / path
        outside = Path(self._outside.name) / "leaf.md"
        outside.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        target.unlink()
        target.symlink_to(outside)

    def external_parent_symlink(self) -> None:
        target = self.root / "docs/history"
        outside = Path(self._outside.name) / "history"
        outside.mkdir()
        (outside / "PLATFORM_SCOPE.md").write_text("Historical platform scope.\n", encoding="utf-8")
        (target / "PLATFORM_SCOPE.md").unlink()
        target.rmdir()
        target.symlink_to(outside, target_is_directory=True)


def temporary_index_fixture(documents: dict[str, str] | None = None) -> TemporaryIndexFixture:
    return TemporaryIndexFixture(documents)


def valid_claim_registry(repo: TemporaryIndexFixture) -> tuple[bytes, bytes, bytes, bytes]:
    del repo
    return tuple((VALID / name).read_bytes() for name in ("registry.json", "base.json", "delta.json", "composed.json"))  # type: ignore[return-value]


def task3_claim_registry() -> tuple[bytes, bytes, bytes, bytes]:
    names = ("fixture-claim-migration-v1.json", "fixture-base-document-universe-v1.json", "fixture-classified-delta-v1.json", "fixture-composed-document-universe-v1.json")
    return tuple((TASK3_VALID / name).read_bytes() for name in names)  # type: ignore[return-value]


def changed(raw: bytes, mutate) -> bytes:
    value = json.loads(raw)
    mutate(value)
    return canonical_bytes(value)


def with_lineage(registry_raw: bytes, base_raw: bytes, delta_raw: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    registry, base, delta = (json.loads(raw) for raw in (registry_raw, base_raw, delta_raw))
    rows = {row["path"]: row for row in base["rows"]}
    rows.update({row["path"]: row for row in delta["rows"]})
    base_raw, delta_raw = canonical_bytes(base), canonical_bytes(delta)
    composed = {
        "schema_version": "gocode.rc0.post-rc0-platform-composed-universe/1",
        "repository_id": "gocode",
        "base_document_universe_payload_sha256": hashlib.sha256(base_raw).hexdigest(),
        "classified_delta_payload_sha256": hashlib.sha256(delta_raw).hexdigest(),
        "composed_document_universe_payload_sha256": hashlib.sha256(canonical_bytes([rows[path] for path in sorted(rows)])).hexdigest(),
        "base_paths": [row["path"] for row in base["rows"]],
        "classified_delta_paths": [row["path"] for row in delta["rows"]],
        "composed_paths": sorted(rows),
    }
    for field in ("base_document_universe_payload_sha256", "classified_delta_payload_sha256", "composed_document_universe_payload_sha256"):
        registry[field] = composed[field]
    return canonical_bytes(registry), base_raw, delta_raw, canonical_bytes(composed)


def overlap_vector() -> tuple[bytes, bytes, bytes, bytes]:
    path = "docs/notes/OVERLAY.md"
    base = canonical_bytes({"schema_version": "gocode.rc0.fixture-base-document-universe/1", "repository_id": "gocode", "rows": [{"path": path, "classification": "governed", "content_sha256": "a" * 64}]})
    delta = canonical_bytes({"schema_version": "gocode.rc0.fixture-classified-delta/1", "repository_id": "gocode", "rows": [{"path": path, "classification": "superseded", "content_sha256": "b" * 64}]})
    registry = canonical_bytes({"schema_version": "gocode.v1-platform-scope-claim-migration/1", "repository_id": "gocode", "registry_revision": 1, "base_document_universe_payload_sha256": "0" * 64, "classified_delta_payload_sha256": "0" * 64, "composed_document_universe_payload_sha256": "0" * 64, "claims": [{"claim_id": "OVERLAY", "literal_needles": ["overlay"], "expected_paths": [path], "disposition": "superseded", "replacement_adr_ids": ["ADR-0015", "ADR-0027"], "owner": "shared", "reason": "Fixture overlay."}]})
    return with_lineage(registry, base, delta)


def _run(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, env=_git_env(root), stdout=subprocess.PIPE)


def _git_env(root: Path) -> dict[str, str]:
    blocked = {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}
    env = {key: value for key, value in os.environ.items() if key not in blocked}
    env["GIT_INDEX_FILE"] = str(root / ".git/index")
    return env


def closure_document(
    path: str,
    adr: str,
    state: str,
    identifier: str | None = None,
    link_target: str | None = None,
) -> str:
    identifier = adr if identifier is None else identifier
    if path.endswith("-v1-platform-scope.md"):
        owner = "gocode-runtime" if path.startswith("docs/adr/") else "gocode-desktop"
        visible = "**Status:** accepted" if owner == "gocode-runtime" else "Accepted."
        return f"---\ntitle: \"V1 Platform Scope\"\nstatus: ready\nowners:\n  - {owner}\n---\n# {identifier}: V1 Platform Scope\n{visible}\n"
    target = link_target or _closure_target(path, adr)
    reference = f"[{identifier}]({target})"
    if path == "docs/adr/README.md":
        return _table(("ADR", "Title", "Status"), ((reference, "V1 Platform Scope", state),))
    if path == "docs/desktop/adr/README.md":
        return _table(("ADR", "Решение", "Статус"), ((reference, "V1 platform scope", state),))
    if path == "docs/decisions/DECISION_LOG.md":
        return decision_log_document(path, adr, (state,), identifier, link_target)
    if path == "docs/desktop/decisions/DECISION_LOG.md":
        return decision_log_document(path, adr, (state,), identifier, link_target)
    if path == "docs/decisions/OPEN_QUESTIONS.md":
        return _table(
            ("ID", "Question", "Context", "Raised", "Status", "Resolved by"),
            (("OQ-007", "Supported platforms v1?", "Shared platform scope", "2026-07-24", state, reference),),
        )
    if path == "docs/desktop/decisions/OPEN_QUESTIONS.md":
        return _table(
            ("ID", "Status", "Decision/question", "Gate/resolution"),
            (("OQ-005", state, "platform floor", reference),),
        )
    raise AssertionError(f"unknown closure path: {path}")


def decision_log_document(
    path: str,
    adr: str,
    states: tuple[str, ...],
    identifier: str | None = None,
    link_target: str | None = None,
) -> str:
    identifier = adr if identifier is None else identifier
    target = link_target or _closure_target(path, adr)
    reference = identifier if link_target is None else f"[{identifier}]({target})"
    if path == "docs/decisions/DECISION_LOG.md":
        rows = tuple((f"2026-08-{9 + index:02d}", f"{state} shared v1 platform scope", reference, state) for index, state in enumerate(states))
        return _table(("Date", "Decision", "ADR", "Status"), rows)
    if path == "docs/desktop/decisions/DECISION_LOG.md":
        rows = tuple((f"2026-08-{9 + index:02d}", f"{state} shared v1 platform scope", reference) for index, state in enumerate(states))
        return _table(("Date", "Decision", "Evidence"), rows)
    raise AssertionError(f"unknown decision-log path: {path}")


def _closure_target(path: str, adr: str) -> str:
    filename = f"{adr}-v1-platform-scope.md"
    return filename if path.endswith("adr/README.md") else f"../adr/{filename}"


def _table(headers: tuple[str, ...], rows: tuple[tuple[str, ...], ...]) -> str:
    header = "| " + " | ".join(headers) + " |\n"
    divider = "|" + "|".join("---" for _ in headers) + "|\n"
    body = "".join("| " + " | ".join(row) + " |\n" for row in rows)
    return header + divider + body


def _documents() -> dict[str, str]:
    closures = {
        "docs/adr/ADR-0027-v1-platform-scope.md": closure_document("docs/adr/ADR-0027-v1-platform-scope.md", "ADR-0027", "Accepted"),
        "docs/adr/README.md": closure_document("docs/adr/README.md", "ADR-0027", "Accepted"),
        "docs/decisions/DECISION_LOG.md": closure_document("docs/decisions/DECISION_LOG.md", "ADR-0027", "Accepted"),
        "docs/decisions/OPEN_QUESTIONS.md": closure_document("docs/decisions/OPEN_QUESTIONS.md", "ADR-0027", "**Resolved**"),
        "docs/desktop/adr/ADR-0015-v1-platform-scope.md": closure_document("docs/desktop/adr/ADR-0015-v1-platform-scope.md", "ADR-0015", "Accepted"),
        "docs/desktop/adr/README.md": closure_document("docs/desktop/adr/README.md", "ADR-0015", "Accepted"),
        "docs/desktop/decisions/DECISION_LOG.md": closure_document("docs/desktop/decisions/DECISION_LOG.md", "ADR-0015", "Accepted"),
        "docs/desktop/decisions/OPEN_QUESTIONS.md": closure_document("docs/desktop/decisions/OPEN_QUESTIONS.md", "ADR-0015", "Closed"),
    }
    return closures | {
        "docs/history/PLATFORM_SCOPE.md": "Historical platform scope.\n",
        "docs/notes/NON_NORMATIVE.md": "This is non-normative platform context.\n",
        "docs/notes/MACOS.md": "macOS production Developer ID\n",
        "docs/notes/MANIFEST.md": "Manifest V1 handoff\n",
        "docs/notes/MOBILE.md": "old mobile platform floor\n",
        "docs/notes/NATIVE.md": "native three-platform production\n",
        "docs/notes/PHASE_10.md": "Phase 10 platform qualification ownership\n",
        "docs/notes/PLATFORM_SCOPE.md": "Windows Server 2025 is the v1 production target.\n",
    }
