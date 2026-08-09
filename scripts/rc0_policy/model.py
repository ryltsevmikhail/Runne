"""Cross-record checks for synthetic local RC0 fixtures.

This module deliberately has no runner, trust loader, selector or authority
writer. It transforms caller-supplied bytes into diagnostics only.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping

from .canonical import canonical_bytes, loads_canonical
from .schemas import validate_schema

EVIDENCE_FILES = (
    "candidate-record.json",
    "source-gate-results.json",
    "test-inventory.json",
    "security-validation.json",
    "documentation-validation.json",
    "fail-closed-disposition.json",
    "artifact-inventory.json",
    "sbom.spdx.json",
    "checksums.txt",
)
FIXTURE_MARKER = "FIXTURE_LOCAL_INPUTS_SATISFIED"
FIXTURE_REJECTED_MARKER = "FIXTURE_LOCAL_INPUTS_REJECTED"
_SUPPORTED_STAGES = {"SOURCE_CANDIDATE", "PRODUCTION_QUALIFICATION"}
_UNSUPPORTED_STAGES = {"RELEASE_APPROVAL", "PUBLICATION_AUTHORIZATION"}
_CHECKSUM_LINE = re.compile(
    r"(?P<sha>[0-9a-f]{64}) (?P<size>0|[1-9][0-9]*) "
    r"(?P<path>[A-Za-z0-9._/+@=-]+)"
)


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
    marker = FIXTURE_MARKER if not diagnostics else FIXTURE_REJECTED_MARKER
    return FixtureValidation(record, canonical_bytes(record), diagnostics, marker)


def parse_checksums_text(raw: bytes) -> dict[str, Any]:
    """Parse the exact checksums.txt grammar into its closed schema model."""
    if not isinstance(raw, bytes) or len(raw) > 65_536:
        raise FixtureValidationError("checksums input must be bounded bytes")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\t" in raw or raw.startswith(b"\xef\xbb\xbf"):
        raise FixtureValidationError("checksums requires BOM-free LF-only text")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise FixtureValidationError("checksums is not strict UTF-8") from error
    lines = text[:-1].split("\n")
    if len(lines) < 5 or any(not line for line in lines):
        raise FixtureValidationError("checksums requires four headers and artifacts")
    header_names = (
        "repository_id",
        "candidate_source_revision",
        "evidence_attempt_id",
        "policy_digest",
    )
    identity: dict[str, str] = {}
    for name, line in zip(header_names, lines[:4], strict=True):
        prefix = name + "="
        if not line.startswith(prefix) or not line[len(prefix) :]:
            raise FixtureValidationError(f"invalid checksums header: {name}")
        identity[name] = line[len(prefix) :]
    if re.fullmatch(r"[0-9a-f]{40}", identity["candidate_source_revision"]) is None:
        raise FixtureValidationError("invalid candidate source revision")
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", identity["evidence_attempt_id"]) is None:
        raise FixtureValidationError("invalid evidence attempt UUIDv7")
    if re.fullmatch(r"[0-9a-f]{64}", identity["policy_digest"]) is None:
        raise FixtureValidationError("invalid policy digest")
    artifacts: list[dict[str, Any]] = []
    for line in lines[4:]:
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise FixtureValidationError("invalid canonical artifact checksum line")
        size = int(match["size"])
        if size > 2**64 - 1:
            raise FixtureValidationError("artifact size exceeds u64")
        artifacts.append(
            {"relative_path": match["path"], "sha256": match["sha"], "size": size}
        )
    paths = [item["relative_path"] for item in artifacts]
    keys = [(item["relative_path"], item["sha256"]) for item in artifacts]
    if paths != sorted(paths, key=lambda value: value.encode("ascii")):
        raise FixtureValidationError("artifact lines are not ASCII-path sorted")
    if len(set(paths)) != len(paths) or len(set(keys)) != len(keys):
        raise FixtureValidationError("duplicate artifact checksum entry")
    return {"schema_id": "gocode.rc0.schema.checksums-text/3", **identity, "artifacts": artifacts}


def fixture_evidence_bundle_digest(entries: Mapping[str, Mapping[str, Any]]) -> str:
    """Exercise the outside-worktree seal framing over caller-supplied blobs."""
    if len(entries) != len(EVIDENCE_FILES):
        raise FixtureValidationError("evidence seal requires exactly nine entries")
    directories: set[PurePosixPath] = set()
    by_name: dict[str, bytes] = {}
    for raw_path, entry in entries.items():
        path = PurePosixPath(raw_path)
        if path.is_absolute() or ".." in path.parts or len(path.parts) != 5:
            raise FixtureValidationError("evidence entries must be direct children")
        if path.parts[:3] != ("docs", "evidence", "rc0-candidates"):
            raise FixtureValidationError("evidence path is outside the RC0 directory")
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
    for name in sorted(EVIDENCE_FILES, key=lambda item: str(parent / item).encode("ascii")):
        path_bytes = str(parent / name).encode("utf-8")
        data = by_name[name]
        digest.update(struct.pack(">I", len(path_bytes)))
        digest.update(path_bytes)
        digest.update(struct.pack(">Q", len(data)))
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def _artifact_keys(records: Any, label: str) -> tuple[set[tuple[str, str]], list[str]]:
    errors: list[str] = []
    keys: set[tuple[str, str]] = set()
    if not isinstance(records, list):
        return set(), [f"{label}: artifacts must be an array"]
    for record in records:
        if not isinstance(record, dict):
            errors.append(f"{label}: artifact must be an object")
            continue
        key = (record.get("relative_path"), record.get("sha256"))
        if not all(isinstance(part, str) for part in key):
            errors.append(f"{label}: malformed artifact key")
        elif key in keys:
            errors.append(f"{label}: duplicate artifact key {key!r}")
        else:
            keys.add(key)
    return keys, errors


def validate_artifact_bijection(
    inventory: Mapping[str, Any], checksums: Mapping[str, Any], spdx: Mapping[str, Any]
) -> tuple[str, ...]:
    sources = (
        ("artifact-inventory", inventory.get("artifacts")),
        ("checksums", checksums.get("artifacts")),
        ("SPDX", spdx.get("artifact_bindings")),
    )
    sets: list[set[tuple[str, str]]] = []
    errors: list[str] = []
    for label, records in sources:
        keys, source_errors = _artifact_keys(records, label)
        sets.append(keys)
        errors.extend(source_errors)
    if not errors and not (sets[0] == sets[1] == sets[2]):
        errors.append("artifact-inventory, checksums and SPDX keys are not an exact bijection")
    if not errors:
        inventory_by_key = {
            (item["relative_path"], item["sha256"]): item for item in inventory["artifacts"]
        }
        checksums_by_key = {
            (item["relative_path"], item["sha256"]): item for item in checksums["artifacts"]
        }
        if any(
            inventory_by_key[key].get("size") != checksums_by_key[key].get("size")
            for key in inventory_by_key
        ):
            errors.append("artifact inventory and checksums size binding mismatch")
        locators = [item.get("locator") for item in inventory["artifacts"]]
        if any(not isinstance(locator, str) or not locator for locator in locators):
            errors.append("artifact locator is missing")
        elif len(set(locators)) != len(locators):
            errors.append("artifact locator is not unique")
    return tuple(errors)


def validate_common_bindings(records: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    fields = ("repository_id", "candidate_source_revision", "evidence_attempt_id", "policy_digest")
    errors: list[str] = []
    for field in fields:
        values = {record.get(field) for record in records.values()}
        if len(values) != 1 or None in values:
            errors.append(f"cross-record binding mismatch: {field}")
    return tuple(errors)


def validate_record_bindings(records: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    """Validate invariants spanning normalized evidence and an external report."""
    evidence = {name: records[name] for name in EVIDENCE_FILES if name in records}
    errors: list[str] = []
    if set(evidence) != set(EVIDENCE_FILES):
        errors.append("normalized evidence requires exactly nine named records")
    errors.extend(validate_common_bindings(evidence))
    profiles = {record.get("profile") for record in evidence.values() if "profile" in record}
    if len(profiles) > 1 or None in profiles:
        errors.append("cross-record binding mismatch: profile")
    candidate = evidence.get("candidate-record.json", {})
    source_sha = candidate.get("candidate_source_revision")
    source = evidence.get("source-gate-results.json", {}).get("capture", {})
    for field in ("head_revision", "captured_origin_main_revision"):
        if source and source.get(field) != source_sha:
            errors.append(f"source capture {field} does not bind candidate source")
    tests = evidence.get("test-inventory.json", {}).get("tests", [])
    if any(test.get("source_sha") != source_sha for test in tests):
        errors.append("test inventory source_sha does not bind candidate source")
    artifact = evidence.get("artifact-inventory.json")
    checksums = evidence.get("checksums.txt")
    spdx = evidence.get("sbom.spdx.json")
    if artifact is not None and checksums is not None and spdx is not None:
        errors.extend(validate_artifact_bijection(artifact, checksums, spdx))
    report = records.get("verification-report.json")
    if report is not None:
        expected = {
            "repository_id": candidate.get("repository_id"),
            "candidate_source_sha": source_sha,
            "evidence_attempt_id": candidate.get("evidence_attempt_id"),
            "policy_digest": candidate.get("policy_digest"),
            "profile": candidate.get("profile"),
        }
        for field, value in expected.items():
            if report.get(field) != value:
                errors.append(f"external report binding mismatch: {field}")
        inventory_bindings = {
            (item.get("relative_path"), item.get("sha256"), item.get("size"), item.get("locator"))
            for item in (artifact or {}).get("artifacts", [])
        }
        report_bindings = {
            (item.get("relative_path"), item.get("sha256"), item.get("size"), item.get("locator"))
            for item in report.get("exact_artifact_bindings", [])
        }
        if inventory_bindings != report_bindings:
            errors.append("external report exact_artifact_bindings mismatch")
        mapping = {"PASS": "PASS", "FAIL": "BLOCKED", "NOT_RUN": "BLOCKED"}
        for gate in report.get("required_gate_results", []):
            if mapping.get(gate.get("execution_outcome")) != gate.get("gate_result"):
                errors.append("required gate mapping is inconsistent")
        errors.extend(validate_stage_dispositions(report.get("stage_dispositions", [])))
    return tuple(errors)


def validate_stage_dispositions(records: list[Mapping[str, Any]]) -> tuple[str, ...]:
    errors: list[str] = []
    for index, record in enumerate(records):
        stage = record.get("stage")
        if stage in _UNSUPPORTED_STAGES:
            allowed = {"stage", "report_stage_disposition"}
            if record.get("report_stage_disposition") != "OUT_OF_SCOPE":
                errors.append(f"[{index}]: unsupported stage must be OUT_OF_SCOPE")
            if set(record) - allowed:
                errors.append(f"[{index}]: unsupported stage cannot carry a gate result or outcome")
        elif stage in _SUPPORTED_STAGES:
            if "report_stage_disposition" in record:
                errors.append(f"[{index}]: supported stage cannot be OUT_OF_SCOPE")
        else:
            errors.append(f"[{index}]: unknown stage")
    return tuple(errors)
