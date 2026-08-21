"""Non-authoritative model façade for synthetic local RC0 fixtures."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping

from .bindings import (
    EVIDENCE_FILES,
    validate_common_bindings,
    validate_record_bindings,
    validate_report_against_policy,
    validate_stage_dispositions,
)
from .canonical import canonical_bytes, loads_canonical
from .rules import (
    parse_checksums_text as _parse_checksums_text,
    validate_artifact_bijection,
    validate_artifact_inventory,
    validate_content_locator,
    validate_policy_inventory,
    validate_portable_relative_path,
    validate_source_capture,
)
from .schemas import validate_schema

FIXTURE_MARKER = "FIXTURE_LOCAL_INPUTS_SATISFIED"
FIXTURE_REJECTED_MARKER = "FIXTURE_LOCAL_INPUTS_REJECTED"


class FixtureValidationError(ValueError):
    """A local fixture violates a structural RC0 invariant."""


@dataclass(frozen=True)
class FixtureValidation:
    record: Any
    canonical: bytes
    diagnostics: tuple[str, ...]
    marker: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "canonical_sha256": hashlib.sha256(self.canonical).hexdigest(),
            "diagnostics": list(self.diagnostics),
            "marker": self.marker,
            "record": self.record,
        }


def validate_fixture(raw: bytes, schema_id: str) -> FixtureValidation:
    """Parse fixture bytes and return non-authoritative schema diagnostics."""
    record = loads_canonical(raw)
    diagnostics = validate_schema(record, schema_id)
    if schema_id in {
        "gocode.rc0.schema.qualification-policy-bundle/3",
        "gocode.rc0.schema.qualification-policy-bundle/4",
    } and isinstance(record, dict):
        diagnostics += validate_policy_inventory(record)
    elif schema_id in {
        "gocode.rc0.schema.artifact-inventory/3",
        "gocode.rc0.schema.artifact-inventory/4",
    } and isinstance(record, dict):
        diagnostics += validate_artifact_inventory(record)
    elif schema_id in {
        "gocode.rc0.schema.source-gate-results/3",
        "gocode.rc0.schema.source-gate-results/4",
    } and isinstance(record, dict):
        diagnostics += validate_source_capture(
            record.get("capture", {}), record.get("candidate_source_revision"), record.get("profile")
        )
    marker = FIXTURE_MARKER if not diagnostics else FIXTURE_REJECTED_MARKER
    return FixtureValidation(record, canonical_bytes(record), diagnostics, marker)


def parse_checksums_text(raw: bytes) -> dict[str, Any]:
    return _parse_checksums_text(raw, FixtureValidationError)


def fixture_evidence_bundle_digest(entries: Mapping[str, Mapping[str, Any]]) -> str:
    """Exercise the outside-worktree seal framing over caller-supplied blobs."""
    if len(entries) != len(EVIDENCE_FILES):
        raise FixtureValidationError("evidence seal requires exactly nine entries")
    directories: set[PurePosixPath] = set()
    by_name: dict[str, bytes] = {}
    for raw_path, entry in entries.items():
        path = PurePosixPath(raw_path)
        if validate_portable_relative_path(raw_path) or str(path) != raw_path:
            raise FixtureValidationError("evidence entry path is not canonical portable relative")
        if len(path.parts) != 5 or path.parts[:3] != ("docs", "evidence", "rc0-candidates"):
            raise FixtureValidationError("evidence entries must be direct RC0 children")
        source = path.parts[3]
        if len(source) != 40 or any(char not in "0123456789abcdef" for char in source):
            raise FixtureValidationError("evidence directory must be a lower-case source SHA")
        if entry.get("mode") != "100644" or entry.get("type") != "blob":
            raise FixtureValidationError("evidence entries must be regular 100644 blobs")
        data = entry.get("data")
        if not isinstance(data, bytes):
            raise FixtureValidationError("fixture blob data must be bytes")
        directories.add(path.parent)
        if path.name in by_name:
            raise FixtureValidationError("duplicate evidence basename")
        by_name[path.name] = data
    if len(directories) != 1 or set(by_name) != set(EVIDENCE_FILES):
        raise FixtureValidationError("evidence seal has missing, extra or split entries")
    digest = hashlib.sha256()
    digest.update(b"GOCODE_RC0_EVIDENCE_V1\0")
    parent = next(iter(directories))
    for name in sorted(EVIDENCE_FILES, key=lambda item: str(parent / item).encode("utf-8")):
        path_bytes = str(parent / name).encode("utf-8")
        data = by_name[name]
        digest.update(struct.pack(">I", len(path_bytes)))
        digest.update(path_bytes)
        digest.update(struct.pack(">Q", len(data)))
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()
