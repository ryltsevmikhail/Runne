"""Shared paths and small immutable fixture helpers for Desktop v1 tests."""

import copy
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CAPABILITY_SCHEMA = ROOT / "docs/schemas/desktop-v1-capabilities-v1.schema.json"
STATUS_SCHEMA = ROOT / "docs/schemas/desktop-v1-capability-status-v2.schema.json"
PROFILE = ROOT / "docs/profiles/desktop-v1-capabilities-v1.json"
PROFILE_DIGEST = ROOT / "docs/profiles/desktop-v1-capabilities-v1.digest"
STATUS = ROOT / "docs/evidence/desktop-v1-capability-status-v2.json"


def load_json_no_duplicates(path: Path) -> object:
    """Load JSON while rejecting duplicate object keys at every nesting level."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def validate_track_stages(schema: dict[str, object], stages: object) -> None:
    """Apply the track-stage array bounds declared by the definition schema."""

    definitions = schema["$defs"]
    if not isinstance(definitions, dict):
        raise ValueError("schema definitions are invalid")
    track = definitions.get("track")
    if not isinstance(track, dict):
        raise ValueError("track schema is invalid")
    properties = track.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("track properties are invalid")
    stage_schema = properties.get("stages")
    if not isinstance(stage_schema, dict) or not isinstance(stages, list):
        raise ValueError("track stages are invalid")
    minimum = stage_schema.get("minItems")
    if not isinstance(minimum, int) or len(stages) < minimum:
        raise ValueError("array has fewer than minItems")
    prefix_items = stage_schema.get("prefixItems")
    if stage_schema.get("items") is False and isinstance(prefix_items, list) and len(stages) > len(prefix_items):
        raise ValueError("array has more than prefixItems")


def definition() -> dict[str, object]:
    """Return an independently mutable copy of the checked-in definition."""

    return copy.deepcopy(load_json_no_duplicates(PROFILE))  # type: ignore[return-value]


def status() -> dict[str, object]:
    """Return an independently mutable copy of the checked-in status."""

    return copy.deepcopy(load_json_no_duplicates(STATUS))  # type: ignore[return-value]


def status_with_track_stages(stages: tuple[int, ...]) -> dict[str, object]:
    """Mark the CAP-SET track gates needed for the supplied track stages verified."""

    value = status()
    tracks = (
        ("GATE-CONTRACT-SCHEMA", "GATE-CLIENT-USE-CASE", "GATE-TYPED-IPC", "GATE-REAL-DATA-UI", "GATE-E2E-RECOVERY"),
        ("GATE-NATIVE-ADMISSION", "GATE-NATIVE-ADAPTER", "GATE-NATIVE-IPC", "GATE-NATIVE-PACKAGED"),
        ("GATE-CONTRACT-SCHEMA", "GATE-CLIENT-USE-CASE", "GATE-TYPED-IPC", "GATE-REAL-DATA-UI", "GATE-E2E-RECOVERY"),
    )
    verified = {gate_id for stage, gates in zip(stages, tracks) for gate_id in gates[:stage // 20]}
    for row in value["gates"]:  # type: ignore[index]
        gate_id = row["gate_id"]
        if gate_id in verified:
            row.update({"disposition": "verified", "blocker_code": None, "evidence_ref": gate_id, "provenance": {"subject_sha256": "1" * 64, "predicate_sha256": "2" * 64}})
    value["evidence_refs"] = [{"id": gate_id, "sha256": "1" * 64} for gate_id in sorted(verified)]  # type: ignore[index]
    return value
