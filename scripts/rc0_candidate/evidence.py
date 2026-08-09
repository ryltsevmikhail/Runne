"""Nine-blob fixture evidence validation and atomic local construction."""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from scripts.rc0_policy.bindings import EVIDENCE_FILES, validate_record_bindings
from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes
from scripts.rc0_policy.model import FixtureValidationError, parse_checksums_text
from scripts.rc0_policy.schemas import validate_schema

from .atomic_publish import AtomicPublishError, publish_private_blobs
from .path_policy import evidence_value_diagnostics, validate_artifact_path
from .source import validate_fixture_evidence_commit

_SHA = re.compile(r"[0-9a-f]{40}")
_SCHEMAS = {
    "candidate-record.json": "gocode.rc0.schema.candidate-record/3",
    "source-gate-results.json": "gocode.rc0.schema.source-gate-results/3",
    "test-inventory.json": "gocode.rc0.schema.test-inventory/3",
    "security-validation.json": "gocode.rc0.schema.security-validation/3",
    "documentation-validation.json": "gocode.rc0.schema.documentation-validation/3",
    "fail-closed-disposition.json": "gocode.rc0.schema.fail-closed-disposition/3",
    "artifact-inventory.json": "gocode.rc0.schema.artifact-inventory/3",
    "sbom.spdx.json": "gocode.rc0.schema.sbom-spdx-2.3/3",
}


class EvidenceConstructionError(ValueError):
    """Fixture evidence cannot be safely constructed."""

@dataclass(frozen=True)
class EvidenceBuildResult:
    directory: Path
    blobs: Mapping[str, bytes]
    evidence_bundle_digest: str

def validate_fixture_evidence_entries(
    source_sha: str, entries: Mapping[str, Mapping[str, Any]]
) -> tuple[str, ...]:
    errors: list[str] = []
    if _SHA.fullmatch(source_sha) is None:
        errors.append("evidence root source SHA is not canonical lower-case hex")
    if set(entries) != set(EVIDENCE_FILES) or len(entries) != len(EVIDENCE_FILES):
        errors.append("evidence diff must add exactly the nine named direct children")
    for name, entry in entries.items():
        if name not in EVIDENCE_FILES or "/" in name or "\\" in name:
            errors.append(f"unexpected evidence path: {name}")
            continue
        if entry.get("mode") != "100644" or entry.get("type") != "blob":
            errors.append(f"evidence entry is not a regular 100644 blob: {name}")
        if not isinstance(entry.get("data"), bytes):
            errors.append(f"evidence entry data is not bytes: {name}")
    return tuple(errors)


def evidence_bundle_digest(source_sha: str, blobs: Mapping[str, bytes]) -> str:
    entries = {
        name: {"mode": "100644", "type": "blob", "data": data}
        for name, data in blobs.items()
    }
    diagnostics = validate_fixture_evidence_entries(source_sha, entries)
    if diagnostics:
        raise EvidenceConstructionError("; ".join(diagnostics))
    prefix = f"docs/evidence/rc0-candidates/{source_sha}/"
    digest = hashlib.sha256(b"GOCODE_RC0_EVIDENCE_V1\0")
    for name in sorted(blobs, key=lambda item: (prefix + item).encode("utf-8")):
        path = (prefix + name).encode("utf-8")
        data = blobs[name]
        digest.update(struct.pack(">I", len(path)))
        digest.update(path)
        digest.update(struct.pack(">Q", len(data)))
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def _artifact_path_diagnostics(records: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for container, field in (
        (records["artifact-inventory.json"], "artifacts"),
        (records["checksums.txt"], "artifacts"),
        (records["sbom.spdx.json"], "artifact_bindings"),
    ):
        for item in container.get(field, []):
            if isinstance(item, dict):
                errors.extend(validate_artifact_path(item.get("relative_path")))
    return errors


def _prepare_blobs(records: Mapping[str, Any]) -> tuple[str, dict[str, bytes]]:
    if set(records) != set(EVIDENCE_FILES) or len(records) != len(EVIDENCE_FILES):
        raise EvidenceConstructionError("construction requires exactly the nine candidate-owned blobs")
    normalized: dict[str, Any] = {}
    blobs: dict[str, bytes] = {}
    diagnostics: list[str] = []
    for name in EVIDENCE_FILES:
        value = records[name]
        if name == "checksums.txt":
            if not isinstance(value, bytes):
                diagnostics.append("checksums.txt must be caller-supplied canonical bytes")
                continue
            try:
                parsed = parse_checksums_text(value)
            except FixtureValidationError as error:
                diagnostics.append(str(error))
                continue
            normalized[name] = parsed
            blobs[name] = value
            diagnostics.extend(validate_schema(parsed, "gocode.rc0.schema.checksums-text/3"))
            if any(not item["relative_path"].isascii() for item in parsed["artifacts"]):
                diagnostics.append("checksums artifact paths must be ASCII")
        else:
            if not isinstance(value, dict):
                diagnostics.append(f"{name} must be an object")
                continue
            diagnostics.extend(evidence_value_diagnostics(value))
            diagnostics.extend(validate_schema(value, _SCHEMAS[name]))
            try:
                blobs[name] = canonical_bytes(value)
            except StrictJSONError as error:
                diagnostics.append(f"{name}: {error}")
                continue
            normalized[name] = value
    if diagnostics:
        raise EvidenceConstructionError("; ".join(diagnostics))
    diagnostics.extend(validate_record_bindings(normalized))
    source_sha = normalized["candidate-record.json"].get("candidate_source_revision")
    if not isinstance(source_sha, str) or _SHA.fullmatch(source_sha) is None:
        diagnostics.append("candidate source SHA is not canonical lower-case hex")
    else:
        diagnostics.extend(_artifact_path_diagnostics(normalized))
    if diagnostics:
        raise EvidenceConstructionError("; ".join(diagnostics))
    return source_sha, blobs


def build_fixture_evidence(
    records: Mapping[str, Any],
    output_root: Path,
    checkout_root: Path,
    publication_hook: Callable[[int, str], None] | None = None,
) -> EvidenceBuildResult:
    """Validate then atomically publish nine owner-private fixture blobs."""
    source_sha, blobs = _prepare_blobs(records)
    try:
        final = publish_private_blobs(
            Path(output_root), Path(checkout_root), source_sha, blobs, publication_hook
        )
    except AtomicPublishError as error:
        raise EvidenceConstructionError(str(error)) from error
    digest = evidence_bundle_digest(source_sha, blobs)
    return EvidenceBuildResult(final, dict(blobs), digest)
