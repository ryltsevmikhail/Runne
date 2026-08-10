"""Deterministic, integer-only scoring for validated capability status."""

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Evaluation:
    score_bps: int
    capability_stages: tuple[tuple[str, int], ...]
    fully_qualified: bool
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class QualificationContext:
    source_content_digest: str
    source_ref: str
    clean_source_paths: bool
    verified_status_provenance_digest: str
    verified_gate_ids: tuple[str, ...]


def evaluate(
    definition: Mapping[str, object],
    status: Mapping[str, object],
    qualification: QualificationContext | None = None,
) -> Evaluation:
    """Score the lowest contiguous track stage for each capability."""

    verified = _verified_gates(status)
    stages: list[tuple[str, int]] = []
    score = 0
    for capability in definition.get("capabilities", []):
        if not isinstance(capability, Mapping):
            continue
        track_stages = [_track_stage(track, verified) for track in capability.get("tracks", []) if isinstance(track, Mapping)]
        current = min(track_stages, default=0)
        capability_id = capability.get("id")
        if not isinstance(capability_id, str):
            continue
        stages.append((capability_id, current))
        weight = capability.get("weight_bps")
        if type(weight) is int:
            score += weight * current // 100
    blockers = _blockers(definition, status, qualification, verified)
    return Evaluation(score, tuple(sorted(stages)), not blockers and score == 10_000, tuple(sorted(blockers)))


def _track_stage(track: Mapping[str, object], verified: set[object]) -> int:
    current = 0
    for row in track.get("stages", []):
        if not isinstance(row, Mapping):
            return current
        gate_ids = row.get("required_gate_ids")
        if not isinstance(gate_ids, list) or not all(gate in verified for gate in gate_ids):
            return current
        stage = row.get("stage")
        if type(stage) is not int:
            return current
        current = stage
    return current


def _verified_gates(status: Mapping[str, object]) -> set[object]:
    evidence = {
        row.get("id")
        for row in status.get("evidence_refs", [])
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    return {
        row.get("gate_id")
        for row in status.get("gates", [])
        if isinstance(row, Mapping)
        and row.get("disposition") == "verified"
        and isinstance(row.get("evidence_ref"), str)
        and row.get("evidence_ref") in evidence
        and not any(word in row["evidence_ref"].lower() for word in ("compile", "stub", "synthetic"))
        and isinstance(row.get("provenance"), Mapping)
    }


def _blockers(
    definition: Mapping[str, object], status: Mapping[str, object], qualification: QualificationContext | None, verified: set[object]
) -> set[str]:
    blockers: set[str] = set()
    for row in status.get("platforms", []):
        if isinstance(row, Mapping) and row.get("disposition") != "verified":
            blockers.add(str(row.get("blocker_code") or "PLATFORM_NOT_VERIFIED"))
    for row in status.get("capabilities", []):
        if isinstance(row, Mapping) and row.get("disposition") != "verified":
            blockers.add(str(row.get("blocker_code") or "CAPABILITY_NOT_VERIFIED"))
    if qualification is None:
        blockers.add("SOURCE_BINDING_NOT_VERIFIED")
        return blockers
    if not qualification.source_ref or not qualification.clean_source_paths:
        blockers.add("SOURCE_BINDING_NOT_VERIFIED")
    if qualification.source_content_digest != status.get("canonical_source_content_sha256"):
        blockers.add("SOURCE_CONTENT_DIGEST_MISMATCH")
    if not qualification.verified_status_provenance_digest:
        blockers.add("STATUS_PROVENANCE_NOT_VERIFIED")
    trusted = set(qualification.verified_gate_ids)
    if not verified <= trusted:
        blockers.add("GATE_PROVENANCE_NOT_VERIFIED")
    return blockers
