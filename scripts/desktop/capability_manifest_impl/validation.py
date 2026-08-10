"""Fail-closed semantic validation of Desktop v1 capability artifacts."""

from collections.abc import Mapping
from pathlib import Path
from subprocess import CalledProcessError

from .io import canonical_source_content_digest, clean_source_paths, has_raw_sha256, load_json, registry_ids, sha256_file


_DEFINITION_KEYS = frozenset({"schema_version", "manifest_id", "score_scale_bps", "foundation_ids", "platforms", "gates", "routes", "capabilities"})
_STATUS_KEYS = frozenset({"schema_version", "manifest_id", "definition_sha256", "canonical_source_content_sha256", "recorded_at", "contract", "selector_list_sha256", "toolchain_identity", "runner_identity", "evidence_refs", "platforms", "gates", "capabilities"})
_STAGES = (20, 40, 60, 80, 100)
_GATE_KINDS = frozenset({"contract", "implementation", "integration", "functional", "recovery", "native_admission", "native_adapter", "native_integration", "native_packaged", "native_qualification"})


def _error(errors: list[str], code: str) -> None:
    errors.append(code)


def _ids(rows: object, field: str, code: str, errors: list[str]) -> set[str]:
    if not isinstance(rows, list):
        _error(errors, code)
        return set()
    values = [row.get(field) for row in rows if isinstance(row, dict)]
    if len(values) != len(rows) or any(not isinstance(item, str) or not item for item in values):
        _error(errors, code)
        return set()
    if len(values) != len(set(values)):
        _error(errors, f"{code}_DUPLICATE")
    return set(values)


def _closed(row: object, keys: set[str], code: str, errors: list[str]) -> bool:
    if not isinstance(row, dict) or set(row) != keys:
        _error(errors, code)
        return False
    return True


def validate_definition(value: object, requirement_ids: set[str], abuse_case_ids: set[str]) -> tuple[str, ...]:
    """Validate closed IDs, dependency graph, stages and total scoring weight."""

    errors: list[str] = []
    if not isinstance(value, dict) or set(value) != _DEFINITION_KEYS:
        return ("DEFINITION_KEYS",)
    if value.get("schema_version") != "desktop-v1-capabilities.v1" or value.get("manifest_id") != "desktop-v1":
        _error(errors, "DEFINITION_IDENTITY")
    if value.get("score_scale_bps") != 10_000:
        _error(errors, "DEFINITION_SCORE_SCALE")
    platform_ids = _ids(value.get("platforms"), "id", "DEFINITION_PLATFORMS", errors)
    gate_ids = _ids(value.get("gates"), "id", "DEFINITION_GATES", errors)
    capabilities = value.get("capabilities")
    capability_ids = _ids(capabilities, "id", "DEFINITION_CAPABILITIES", errors)
    if not isinstance(capabilities, list):
        return tuple(sorted(errors))
    for platform in value.get("platforms", []):
        _closed(platform, {"id", "operating_system", "minimum_version", "architecture", "target_triple"}, "DEFINITION_PLATFORM_KEYS", errors)
    for gate in value.get("gates", []):
        if _closed(gate, {"id", "kind", "platform_ids"}, "DEFINITION_GATE_KEYS", errors):
            if gate["kind"] not in _GATE_KINDS or not isinstance(gate["platform_ids"], list) or not set(gate["platform_ids"]) <= platform_ids:
                _error(errors, f"DEFINITION_GATE_VALUE:{gate['id']}")
    for route in value.get("routes", []):
        _closed(route, {"id", "path", "owner"}, "DEFINITION_ROUTE_KEYS", errors)
    if sum(item.get("weight_bps", 0) for item in capabilities if isinstance(item, dict) and type(item.get("weight_bps")) is int) != 10_000:
        _error(errors, "DEFINITION_WEIGHT_TOTAL")
    graph: dict[str, set[str]] = {}
    for capability in capabilities:
        if not isinstance(capability, dict) or not isinstance(capability.get("id"), str):
            continue
        capability_id = capability["id"]
        if not _closed(capability, {"id", "priority", "weight_bps", "build_requires", "qualification_requires", "platform_ids", "requirement_ids", "abuse_case_ids", "required_gate_ids", "tracks"}, "DEFINITION_CAPABILITY_KEYS", errors):
            continue
        for field, known, code in (("requirement_ids", requirement_ids, "DEFINITION_UNKNOWN_REQUIREMENT"), ("abuse_case_ids", abuse_case_ids, "DEFINITION_UNKNOWN_ABUSE_CASE")):
            refs = capability.get(field)
            if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
                _error(errors, f"{code}:{capability_id}")
            else:
                for ref in refs:
                    if ref not in known:
                        _error(errors, f"{code}:{capability_id}:{ref}")
        refs = capability.get("build_requires", [])
        graph[capability_id] = {ref for ref in refs if isinstance(ref, str) and ref.startswith("CAP-")}
        for ref in graph[capability_id]:
            if ref not in capability_ids:
                _error(errors, f"DEFINITION_UNKNOWN_DEPENDENCY:{capability_id}:{ref}")
        if not set(capability.get("platform_ids", [])) <= platform_ids:
            _error(errors, f"DEFINITION_UNKNOWN_PLATFORM:{capability_id}")
        if not set(capability.get("required_gate_ids", [])) <= gate_ids:
            _error(errors, f"DEFINITION_UNKNOWN_GATE:{capability_id}")
        for track in capability.get("tracks", []):
            if not _closed(track, {"id", "stage_profile", "component_owner", "stages"}, f"DEFINITION_TRACK:{capability_id}", errors):
                _error(errors, f"DEFINITION_TRACK:{capability_id}")
                continue
            stages = track.get("stages")
            track_id = track.get("id", "unknown")
            if not isinstance(stages, list) or [stage.get("stage") for stage in stages if isinstance(stage, dict)] != list(_STAGES):
                _error(errors, f"DEFINITION_NONCONTIGUOUS_STAGES:{capability_id}:{track_id}")
                continue
            for stage in stages:
                if not _closed(stage, {"stage", "required_gate_ids"}, f"DEFINITION_STAGE:{capability_id}:{track_id}", errors):
                    continue
                if not set(stage.get("required_gate_ids", [])) <= gate_ids:
                    _error(errors, f"DEFINITION_UNKNOWN_STAGE_GATE:{capability_id}:{track_id}")
    visited: set[str] = set()
    active: set[str] = set()
    def visit(node: str) -> bool:
        if node in active:
            return True
        if node in visited:
            return False
        visited.add(node); active.add(node)
        found = any(visit(child) for child in graph.get(node, set()))
        active.remove(node)
        return found
    if any(visit(node) for node in graph):
        _error(errors, "DEFINITION_DEPENDENCY_CYCLE")
    return tuple(sorted(set(errors)))


def validate_status(definition: Mapping[str, object], status: object) -> tuple[str, ...]:
    """Validate closed factual status rows and evidence/provenance references."""

    errors: list[str] = []
    if not isinstance(status, dict) or set(status) != _STATUS_KEYS:
        return ("STATUS_KEYS",)
    if status.get("schema_version") != "desktop-v1-capability-status.v1" or status.get("manifest_id") != definition.get("manifest_id"):
        _error(errors, "STATUS_IDENTITY")
    gates = definition.get("gates", [])
    platforms = definition.get("platforms", [])
    capabilities = definition.get("capabilities", [])
    known_gates = {row.get("id") for row in gates if isinstance(row, dict)}
    known_platforms = {row.get("id") for row in platforms if isinstance(row, dict)}
    known_capabilities = {row.get("id") for row in capabilities if isinstance(row, dict)}
    evidence = status.get("evidence_refs")
    evidence_ids = _ids(evidence, "id", "STATUS_EVIDENCE", errors)
    for row in evidence if isinstance(evidence, list) else []:
        if not isinstance(row, dict) or set(row) != {"id", "sha256"} or not _sha(row.get("sha256")):
            _error(errors, "STATUS_EVIDENCE")
    for row in status.get("platforms", []) if isinstance(status.get("platforms"), list) else []:
        if _closed(row, {"platform_id", "disposition", "blocker_code"}, "STATUS_PLATFORM_KEYS", errors) and row["disposition"] not in {"verified", "not_recorded", "blocked", "unsupported"}:
            _error(errors, f"STATUS_PLATFORM_DISPOSITION:{row['platform_id']}")
    for row in status.get("capabilities", []) if isinstance(status.get("capabilities"), list) else []:
        if _closed(row, {"capability_id", "disposition", "blocker_code"}, "STATUS_CAPABILITY_KEYS", errors) and row["disposition"] not in {"verified", "blocked"}:
            _error(errors, f"STATUS_CAPABILITY_DISPOSITION:{row['capability_id']}")
    _rows(status.get("platforms"), "platform_id", known_platforms, "STATUS", "verified", errors)
    _rows(status.get("gates"), "gate_id", known_gates, "STATUS", "verified", errors)
    _rows(status.get("capabilities"), "capability_id", known_capabilities, "STATUS", "verified", errors)
    for row in status.get("gates", []) if isinstance(status.get("gates"), list) else []:
        if not isinstance(row, dict):
            continue
        gate_id = row.get("gate_id")
        disposition = row.get("disposition")
        expected = {"gate_id", "disposition", "blocker_code"}
        if disposition == "verified":
            expected |= {"evidence_ref", "provenance"}
        if set(row) != expected:
            _error(errors, f"STATUS_GATE_KEYS:{gate_id}")
        if disposition not in {"verified", "not_recorded", "blocked"}:
            _error(errors, f"STATUS_GATE_DISPOSITION:{gate_id}")
        if disposition == "verified":
            provenance = row.get("provenance")
            toolchain = status.get("toolchain_identity")
            runner = status.get("runner_identity")
            identities_recorded = isinstance(toolchain, dict) and toolchain.get("status") == "recorded" and isinstance(runner, dict) and runner.get("status") == "recorded"
            if row.get("blocker_code") is not None or row.get("evidence_ref") not in evidence_ids or not isinstance(provenance, dict) or set(provenance) != {"subject_sha256", "predicate_sha256"} or not all(_sha(provenance.get(key)) for key in provenance) or not identities_recorded:
                _error(errors, f"STATUS_UNTRUSTED_EVIDENCE:{gate_id}")
            if isinstance(row.get("evidence_ref"), str) and any(word in row["evidence_ref"].lower() for word in ("compile", "stub", "synthetic")):
                _error(errors, f"STATUS_UNTRUSTED_EVIDENCE:{gate_id}")
    verified = [row for row in status.get("gates", []) if isinstance(row, dict) and row.get("disposition") == "verified"]
    refs = [row.get("evidence_ref") for row in verified]
    if len(refs) != len(set(refs)):
        _error(errors, f"STATUS_REUSED_EVIDENCE:{next(ref for ref in refs if refs.count(ref) > 1)}")
    return tuple(sorted(set(errors)))


def _sha(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _rows(rows: object, field: str, known: set[object], prefix: str, _verified: str, errors: list[str]) -> None:
    identifiers = _ids(rows, field, f"{prefix}_{field.upper()}S", errors)
    for expected in sorted(known - identifiers):
        _error(errors, f"{prefix}_MISSING_{field[:-3].upper()}:{expected}")
    for actual in identifiers - known:
        _error(errors, f"{prefix}_UNKNOWN_{field[:-3].upper()}:{actual}")


def validate_repository(root: Path, *, verify_source_ref: str | None = None) -> tuple[str, ...]:
    """Validate immutable artifact linkage and the semantic definition/status graph."""

    profile = root / "docs/profiles/desktop-v1-capabilities-v1.json"
    status_path = root / "docs/evidence/desktop-v1-capability-status-v1.json"
    errors: list[str] = []
    try:
        definition = load_json(profile)
        status = load_json(status_path)
        if not has_raw_sha256(profile.read_bytes(), profile.with_suffix(".digest").read_text(encoding="utf-8")):
            _error(errors, "DEFINITION_RAW_DIGEST_MISMATCH")
        if isinstance(status, dict) and status.get("definition_sha256") != sha256_file(profile):
            _error(errors, "STATUS_DEFINITION_DIGEST_MISMATCH")
        requirements = registry_ids(root / "docs/desktop/00-foundation/REQUIREMENTS.md", "REQ-")
        abuse_cases = registry_ids(root / "docs/desktop/07-testing/SECURITY_ABUSE_CASES.md", "SA-")
        errors.extend(validate_definition(definition, requirements, abuse_cases))
        if isinstance(definition, Mapping):
            errors.extend(validate_status(definition, status))
        else:
            _error(errors, "DEFINITION_KEYS")
        if verify_source_ref is not None:
            if not clean_source_paths(root):
                _error(errors, "SOURCE_PATHS_DIRTY")
            if isinstance(status, dict) and status.get("canonical_source_content_sha256") != canonical_source_content_digest(root, verify_source_ref):
                _error(errors, "SOURCE_CONTENT_DIGEST_MISMATCH")
        if isinstance(status, dict):
            for evidence in status.get("evidence_refs", []):
                if not isinstance(evidence, dict) or not isinstance(evidence.get("id"), str):
                    continue
                evidence_path = root / "docs/evidence" / evidence["id"]
                if evidence_path.parent != root / "docs/evidence" or not evidence_path.is_file() or evidence.get("sha256") != sha256_file(evidence_path):
                    _error(errors, f"EVIDENCE_DIGEST_MISMATCH:{evidence.get('id')}")
    except (CalledProcessError, OSError, ValueError) as error:
        _error(errors, f"REPOSITORY_READ_ERROR:{error}")
    return tuple(sorted(set(errors)))
