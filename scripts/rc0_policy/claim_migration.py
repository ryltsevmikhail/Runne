"""Closed, fixture-only validation for platform claim migration records."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from scripts.rc0_policy.adjunct_schema_validation import (
    AdjunctSchemaValidationError,
    parse_adjunct_schema,
    validate_adjunct_schema_instance,
)
from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical
from scripts.rc0_policy.claim_closure_tables import validate_closure_table
from scripts.rc0_policy.governance_status import GovernanceStatusFailure, parse_accepted_adr


ROOT = Path(__file__).resolve().parents[2]
_SCHEMAS = {
    "claim": ("v1-platform-scope-claim-migration-v1.schema.json", "gocode.v1-platform-scope-claim-migration/1"),
    "composed": ("post-rc0-platform-composed-universe-v1.schema.json", "gocode.rc0.post-rc0-platform-composed-universe/1"),
}
_CLOSURES = {
    "ADR-0027": (("docs/adr/ADR-0027-v1-platform-scope.md", "runtime", "adr"), ("docs/adr/README.md", "runtime", "accepted"), ("docs/decisions/DECISION_LOG.md", "runtime", "accepted"), ("docs/decisions/OPEN_QUESTIONS.md", "runtime", "closed")),
    "ADR-0015": (("docs/desktop/adr/ADR-0015-v1-platform-scope.md", "desktop", "adr"), ("docs/desktop/adr/README.md", "desktop", "accepted"), ("docs/desktop/decisions/DECISION_LOG.md", "desktop", "accepted"), ("docs/desktop/decisions/OPEN_QUESTIONS.md", "desktop", "closed")),
}


class ClaimMigrationFailure(ValueError):
    """A fixture migration record is outside the closed contract."""


@dataclass(frozen=True)
class ClaimOccurrence:
    claim_id: str
    literal: str
    path: str


def tracked_markdown_paths(repo_root: Path) -> Sequence[str]:
    try:
        result = subprocess.run(
            ("git", "-C", str(repo_root), "ls-files", "-z"), check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_git_env(),
        )
        paths = tuple(item.decode("utf-8", errors="strict") for item in result.stdout.split(b"\0") if item)
    except (OSError, UnicodeDecodeError, subprocess.CalledProcessError) as error:
        raise ClaimMigrationFailure("CLAIM_TRACKED_PATHS_UNAVAILABLE") from error
    return tuple(sorted(path for path in paths if path.endswith((".md", ".markdown"))))


def validate_claim_registry(
    repo_root: Path,
    registry_raw: bytes,
    base_document_universe_raw: bytes,
    classified_delta_raw: bytes,
    composed_document_universe_raw: bytes,
) -> Sequence[ClaimOccurrence]:
    registry = _document(registry_raw, "CLAIM_REGISTRY_INVALID")
    composed = _document(composed_document_universe_raw, "CLAIM_COMPOSED_UNIVERSE_INVALID")
    _schema(registry, "claim", "CLAIM_REGISTRY_SCHEMA_INVALID")
    _schema(composed, "composed", "CLAIM_COMPOSED_UNIVERSE_SCHEMA_INVALID")
    base = _rows(base_document_universe_raw, "gocode.rc0.fixture-base-document-universe/1")
    delta = _rows(classified_delta_raw, "gocode.rc0.fixture-classified-delta/1")
    _lineage(registry, composed, base, delta, base_document_universe_raw, classified_delta_raw)
    _claims(registry["claims"], delta)
    paths = tracked_markdown_paths(repo_root)
    occurrences = _occurrences(repo_root, paths, registry["claims"])
    if any(claim["disposition"] == "superseded" for claim in registry["claims"]):
        _closures(repo_root, paths)
    if tuple(paths) != tuple(composed["composed_paths"]):
        _fail("CLAIM_TRACKED_PATH_SET_MISMATCH")
    return tuple(occurrences)


def _document(raw: bytes, code: str) -> dict[str, object]:
    try:
        value = loads_canonical(raw)
    except (StrictJSONError, TypeError) as error:
        raise ClaimMigrationFailure(code) from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        _fail(code)
    return value


def _schema(value: dict[str, object], name: str, code: str) -> None:
    filename, schema_id = _SCHEMAS[name]
    try:
        schema = parse_adjunct_schema((ROOT / "docs/schemas" / filename).read_bytes(), schema_id)
        if validate_adjunct_schema_instance(schema, value):
            _fail(code)
    except (AdjunctSchemaValidationError, OSError, StrictJSONError) as error:
        raise ClaimMigrationFailure(code) from error


def _rows(raw: bytes, schema_version: str) -> list[dict[str, object]]:
    value = _document(raw, "CLAIM_LINEAGE_MISMATCH")
    if set(value) != {"repository_id", "rows", "schema_version"} or value.get("repository_id") != "gocode" or value.get("schema_version") != schema_version or type(value.get("rows")) is not list:
        _fail("CLAIM_LINEAGE_MISMATCH")
    rows = value["rows"]
    if not rows or any(not _row(row) for row in rows) or rows != sorted(rows, key=lambda row: row["path"]) or len({row["path"] for row in rows}) != len(rows):
        _fail("CLAIM_LINEAGE_MISMATCH")
    return rows


def _row(row: object) -> bool:
    return type(row) is dict and set(row) == {"path", "classification", "content_sha256"} and _path(row["path"]) and type(row["classification"]) is str and bool(row["classification"]) and _digest(row["content_sha256"])


def _lineage(registry, composed, base, delta, base_raw, delta_raw) -> None:
    base_paths, delta_paths = [row["path"] for row in base], [row["path"] for row in delta]
    rows = {row["path"]: row for row in base + delta}
    digest = _sha(canonical_bytes([rows[path] for path in sorted(rows)]))
    expected = (_sha(base_raw), _sha(delta_raw), digest)
    keys = ("base_document_universe_payload_sha256", "classified_delta_payload_sha256", "composed_document_universe_payload_sha256")
    if any(item.get(key) != value for item in (registry, composed) for key, value in zip(keys, expected)) or composed["base_paths"] != base_paths or composed["classified_delta_paths"] != delta_paths or composed["composed_paths"] != sorted(rows):
        _fail("CLAIM_LINEAGE_MISMATCH")


def _claims(claims: object, delta: list[dict[str, object]]) -> None:
    if type(claims) is not list or claims != sorted(claims, key=lambda row: row["claim_id"]) or len({row["claim_id"] for row in claims}) != len(claims):
        _fail("CLAIM_REGISTRY_INVALID")
    paths: dict[str, str] = {}
    for claim in claims:
        if claim["literal_needles"] != sorted(set(claim["literal_needles"])) or claim["expected_paths"] != sorted(set(claim["expected_paths"])):
            _fail("CLAIM_REGISTRY_INVALID")
        if not claim["reason"].strip():
            _fail("CLAIM_REGISTRY_INVALID")
        if claim["disposition"] == "non_normative_exclusion" and (not claim["owner"] or claim["replacement_adr_ids"]):
            _fail("CLAIM_REGISTRY_INVALID")
        if claim["disposition"] == "superseded" and (claim["owner"] != "shared" or claim["replacement_adr_ids"] != ["ADR-0015", "ADR-0027"]):
            _fail("CLAIM_REGISTRY_INVALID")
        for path in claim["expected_paths"]:
            if path in paths:
                _fail("CLAIM_LINEAGE_MISMATCH")
            paths[path] = claim["disposition"]
    if sorted(paths) != [row["path"] for row in delta]:
        _fail("CLAIM_LINEAGE_MISMATCH")
    if any(paths[row["path"]] != row["classification"] for row in delta):
        _fail("CLAIM_DELTA_DISPOSITION_MISMATCH")


def _occurrences(root: Path, paths: Sequence[str], claims: list[dict[str, object]]) -> list[ClaimOccurrence]:
    result = []
    for claim in claims:
        for literal in claim["literal_needles"]:
            needle = literal.encode("utf-8", errors="strict")
            actual = sorted(path for path in paths if needle in _read(root, path))
            if actual != claim["expected_paths"]:
                _fail("CLAIM_EXPECTED_PATH_SET_MISMATCH")
            result.extend(ClaimOccurrence(claim["claim_id"], literal, path) for path in actual)
    return result


def _closures(root: Path, paths: Sequence[str]) -> None:
    for adr, entries in _CLOSURES.items():
        for path, owner, kind in entries:
            if path not in paths or not _closure(_read(root, path), path, adr, owner, kind):
                _fail("CLAIM_ADR_CLOSURE_MISMATCH")


def _read(root: Path, path: str) -> bytes:
    try:
        candidate, resolved_root = root, root.resolve(strict=True)
        for part in Path(path).parts:
            candidate /= part
            mode = os.lstat(candidate).st_mode
            if stat.S_ISLNK(mode) or (part != Path(path).parts[-1] and not stat.S_ISDIR(mode)):
                _fail("CLAIM_TRACKED_PATH_UNSAFE")
        if not stat.S_ISREG(os.lstat(candidate).st_mode) or not candidate.resolve(strict=True).is_relative_to(resolved_root):
            _fail("CLAIM_TRACKED_PATH_UNSAFE")
        state = subprocess.run(("git", "-C", str(root), "diff", "--quiet", "--", path), env=_git_env()).returncode
        if state == 1:
            _fail("CLAIM_TRACKED_DOCUMENT_UNSTAGED")
        if state:
            _fail("CLAIM_TRACKED_PATHS_UNAVAILABLE")
        return candidate.read_bytes()
    except OSError as error:
        raise ClaimMigrationFailure("CLAIM_TRACKED_PATH_UNSAFE") from error


def _closure(raw: bytes, path: str, adr: str, owner: str, kind: str) -> bool:
    if kind == "adr":
        try:
            parse_accepted_adr(raw, adr, owner)
            return True
        except GovernanceStatusFailure:
            return False
    return validate_closure_table(raw, path, adr)


def _git_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}}


def _path(value: object) -> bool:
    return type(value) is str and value.endswith((".md", ".markdown")) and not value.startswith("/") and "//" not in value and "/../" not in f"/{value}/" and "/./" not in f"/{value}/" and "\0" not in value


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fail(code: str) -> None:
    raise ClaimMigrationFailure(code)
