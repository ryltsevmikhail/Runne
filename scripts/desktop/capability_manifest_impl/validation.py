"""Fail-closed semantic validation of Desktop v1 capability artifacts."""

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
import re
from subprocess import CalledProcessError

from .io import canonical_source_content_digest, clean_source_paths, has_raw_sha256, is_sha256, load_json, registry_ids, resolve_commit, sha256_file


_DEFINITION = {"schema_version", "manifest_id", "score_scale_bps", "foundation_ids", "platforms", "gates", "routes", "capabilities"}
_STATUS = {"schema_version", "manifest_id", "definition_sha256", "canonical_source_content_sha256", "recorded_at", "contract", "selector_list_sha256", "toolchain_identity", "runner_identity", "evidence_refs", "platforms", "gates", "capabilities"}
_GATE_KINDS = {"contract", "implementation", "integration", "functional", "recovery", "native_admission", "native_adapter", "native_integration", "native_packaged", "native_qualification"}
_IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9-]*$")
_FOUNDATION = re.compile(r"^FOUND-[0-9]{2}$")


def _add(errors: list[str], code: str) -> None:
    errors.append(code)


def _closed(value: object, keys: set[str], code: str, errors: list[str]) -> dict[str, object] | None:
    if not isinstance(value, dict) or set(value) != keys:
        _add(errors, code)
        return None
    return value


def _ids(rows: object, field: str, code: str, errors: list[str]) -> set[str]:
    if not isinstance(rows, list):
        _add(errors, code)
        return set()
    values = [row.get(field) for row in rows if isinstance(row, dict)]
    if len(values) != len(rows) or any(not isinstance(value, str) or not value for value in values) or len(values) != len(set(values)):
        _add(errors, code)
        return set()
    return set(values)


def _id_list(value: object, known: set[str], code: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not _IDENTIFIER.fullmatch(item) for item in value) or len(value) != len(set(value)):
        _add(errors, code)
        return []
    for item in value:
        if item not in known:
            _add(errors, f"{code}:{item}")
    return value


def validate_definition(value: object, requirement_ids: set[str], abuse_case_ids: set[str]) -> tuple[str, ...]:
    """Validate the complete closed definition shape and cross-reference graph."""

    errors: list[str] = []
    definition = _closed(value, _DEFINITION, "DEFINITION_KEYS", errors)
    if definition is None:
        return tuple(errors)
    if definition["schema_version"] != "desktop-v1-capabilities.v1" or definition["manifest_id"] != "desktop-v1" or definition["score_scale_bps"] != 10_000:
        _add(errors, "DEFINITION_IDENTITY")
    foundations = definition["foundation_ids"]
    if not isinstance(foundations, list) or not foundations or any(not isinstance(item, str) or not _FOUNDATION.fullmatch(item) for item in foundations) or len(foundations) != len(set(foundations)):
        _add(errors, "DEFINITION_FOUNDATIONS"); foundations = []
    foundation_ids = set(foundations)
    platform_ids = _ids(definition["platforms"], "id", "DEFINITION_PLATFORMS", errors)
    gate_ids = _ids(definition["gates"], "id", "DEFINITION_GATES", errors)
    capability_ids = _ids(definition["capabilities"], "id", "DEFINITION_CAPABILITIES", errors)
    _ids(definition["routes"], "id", "DEFINITION_ROUTES", errors)
    for row in definition["platforms"] if isinstance(definition["platforms"], list) else []:
        item = _closed(row, {"id", "operating_system", "minimum_version", "architecture", "target_triple"}, "DEFINITION_PLATFORM", errors)
        if item and (not _IDENTIFIER.fullmatch(str(item["id"])) or item["operating_system"] not in {"macos", "windows", "linux"} or item["architecture"] not in {"arm64", "x86_64"} or not all(isinstance(item[key], str) and item[key] for key in ("minimum_version", "target_triple"))):
            _add(errors, f"DEFINITION_PLATFORM_VALUE:{item['id']}")
    for row in definition["gates"] if isinstance(definition["gates"], list) else []:
        item = _closed(row, {"id", "kind", "platform_ids"}, "DEFINITION_GATE", errors)
        if item:
            _id_list(item["platform_ids"], platform_ids, "DEFINITION_GATE_PLATFORM", errors)
            if item["kind"] not in _GATE_KINDS: _add(errors, f"DEFINITION_GATE_VALUE:{item['id']}")
    for row in definition["routes"] if isinstance(definition["routes"], list) else []:
        item = _closed(row, {"id", "path", "owner"}, "DEFINITION_ROUTE", errors)
        if item and (not re.fullmatch(r"ROUTE-[A-Z0-9-]+", str(item["id"])) or not all(isinstance(item[key], str) and item[key] for key in ("path", "owner"))):
            _add(errors, "DEFINITION_ROUTE_VALUE")
    capabilities = definition["capabilities"] if isinstance(definition["capabilities"], list) else []
    if sum(item.get("weight_bps", 0) for item in capabilities if isinstance(item, dict) and type(item.get("weight_bps")) is int) != 10_000:
        _add(errors, "DEFINITION_WEIGHT_TOTAL")
    graph: dict[str, set[str]] = {}
    for row in capabilities:
        item = _closed(row, {"id", "priority", "weight_bps", "build_requires", "qualification_requires", "platform_ids", "requirement_ids", "abuse_case_ids", "required_gate_ids", "tracks"}, "DEFINITION_CAPABILITY", errors)
        if item is None or not isinstance(item["id"], str):
            continue
        identifier = item["id"]
        if not re.fullmatch(r"CAP-[A-Z]{3}", identifier) or item["priority"] != "P0" or type(item["weight_bps"]) is not int or not 1 <= item["weight_bps"] <= 10_000:
            _add(errors, f"DEFINITION_CAPABILITY_VALUE:{identifier}")
        build = _id_list(item["build_requires"], foundation_ids | capability_ids, f"DEFINITION_UNKNOWN_DEPENDENCY:{identifier}", errors)
        _id_list(item["qualification_requires"], foundation_ids, f"DEFINITION_UNKNOWN_QUALIFICATION:{identifier}", errors)
        _id_list(item["platform_ids"], platform_ids, f"DEFINITION_UNKNOWN_PLATFORM:{identifier}", errors)
        _id_list(item["required_gate_ids"], gate_ids, f"DEFINITION_UNKNOWN_GATE:{identifier}", errors)
        _id_list(item["requirement_ids"], requirement_ids, f"DEFINITION_UNKNOWN_REQUIREMENT:{identifier}", errors)
        _id_list(item["abuse_case_ids"], abuse_case_ids, f"DEFINITION_UNKNOWN_ABUSE_CASE:{identifier}", errors)
        graph[identifier] = {dependency for dependency in build if dependency.startswith("CAP-")}
        tracks = item["tracks"]
        if not isinstance(tracks, list) or not tracks or len({track.get("id") for track in tracks if isinstance(track, dict)}) != len(tracks):
            _add(errors, f"DEFINITION_TRACKS:{identifier}"); continue
        for track in tracks:
            entry = _closed(track, {"id", "stage_profile", "component_owner", "stages"}, f"DEFINITION_TRACK:{identifier}", errors)
            if entry is None: continue
            track_id = entry["id"]
            if not isinstance(track_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", track_id) or entry["stage_profile"] not in {"runtime-backed", "renderer-owned", "native-owned"} or entry["component_owner"] not in {"runtime", "apps/desktop", "tauri-host"}:
                _add(errors, f"DEFINITION_TRACK_VALUE:{identifier}:{track_id}")
            stages = entry["stages"]
            if not isinstance(stages, list) or [stage.get("stage") for stage in stages if isinstance(stage, dict)] != [20, 40, 60, 80, 100]:
                _add(errors, f"DEFINITION_NONCONTIGUOUS_STAGES:{identifier}:{track_id}"); continue
            for stage in stages:
                step = _closed(stage, {"stage", "required_gate_ids"}, f"DEFINITION_STAGE:{identifier}:{track_id}", errors)
                if step: _id_list(step["required_gate_ids"], gate_ids, f"DEFINITION_UNKNOWN_STAGE_GATE:{identifier}:{track_id}", errors)
    active: set[str] = set(); complete: set[str] = set()
    def visit(node: str) -> bool:
        if node in active: return True
        if node in complete: return False
        active.add(node); found = any(visit(child) for child in graph.get(node, set())); active.remove(node); complete.add(node)
        return found
    if any(visit(node) for node in graph): _add(errors, "DEFINITION_DEPENDENCY_CYCLE")
    return tuple(sorted(set(errors)))


def validate_status(definition: Mapping[str, object], status: object) -> tuple[str, ...]:
    """Validate the complete closed factual status shape independent of disk I/O."""

    errors: list[str] = []
    value = _closed(status, _STATUS, "STATUS_KEYS", errors)
    if value is None: return tuple(errors)
    if value["schema_version"] != "desktop-v1-capability-status.v1" or value["manifest_id"] != definition.get("manifest_id"): _add(errors, "STATUS_IDENTITY")
    if not all(is_sha256(value[key]) for key in ("definition_sha256", "canonical_source_content_sha256", "selector_list_sha256")): _add(errors, "STATUS_SELECTOR_DIGEST")
    recorded_at = value["recorded_at"]
    try:
        if not isinstance(recorded_at, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", recorded_at): raise ValueError
        datetime.fromisoformat(recorded_at.replace("Z", "+00:00"))
    except ValueError: _add(errors, "STATUS_RECORDED_AT")
    contract = _closed(value["contract"], {"profile_id", "profile_sha256", "bundle_sha256"}, "STATUS_CONTRACT", errors)
    if contract and (contract["profile_id"] != "gocode-ui-client/1" or not is_sha256(contract["profile_sha256"]) or not is_sha256(contract["bundle_sha256"])): _add(errors, "STATUS_CONTRACT")
    toolchain = _closed(value["toolchain_identity"], {"status", "name", "version"}, "STATUS_TOOLCHAIN", errors)
    runner = _closed(value["runner_identity"], {"status", "runner_id", "image_sha256"}, "STATUS_RUNNER", errors)
    if toolchain:
        if toolchain["status"] == "recorded": valid_toolchain = all(isinstance(toolchain[key], str) and toolchain[key] for key in ("name", "version"))
        elif toolchain["status"] == "not_recorded": valid_toolchain = toolchain["name"] is None and toolchain["version"] is None
        else: valid_toolchain = False
        if not valid_toolchain: _add(errors, "STATUS_TOOLCHAIN")
    if runner:
        if runner["status"] == "recorded": valid_runner = isinstance(runner["runner_id"], str) and bool(runner["runner_id"]) and is_sha256(runner["image_sha256"])
        elif runner["status"] == "not_recorded": valid_runner = runner["runner_id"] is None and runner["image_sha256"] is None
        else: valid_runner = False
        if not valid_runner: _add(errors, "STATUS_RUNNER")
    evidence = _ids(value["evidence_refs"], "id", "STATUS_EVIDENCE", errors)
    for row in value["evidence_refs"] if isinstance(value["evidence_refs"], list) else []:
        if not _closed(row, {"id", "sha256"}, "STATUS_EVIDENCE", errors) or not is_sha256(row["sha256"]): _add(errors, "STATUS_EVIDENCE")
    known = {"platforms": {row.get("id") for row in definition.get("platforms", []) if isinstance(row, dict)}, "gates": {row.get("id") for row in definition.get("gates", []) if isinstance(row, dict)}, "capabilities": {row.get("id") for row in definition.get("capabilities", []) if isinstance(row, dict)}}
    specs = (("platforms", "platform_id", {"verified", "not_recorded", "blocked", "unsupported"}), ("gates", "gate_id", {"verified", "not_recorded", "blocked"}), ("capabilities", "capability_id", {"verified", "blocked"}))
    verified_refs: list[str] = []
    for group, field, dispositions in specs:
        rows = value[group]; ids = _ids(rows, field, f"STATUS_{group.upper()}", errors)
        for identifier in sorted(known[group] - ids): _add(errors, f"STATUS_MISSING_{field[:-3].upper()}:{identifier}")
        for identifier in ids - known[group]: _add(errors, f"STATUS_UNKNOWN_{field[:-3].upper()}:{identifier}")
        for row in rows if isinstance(rows, list) else []:
            extra = {"gate_id", "disposition", "blocker_code", "evidence_ref", "provenance"} if group == "gates" and isinstance(row, dict) and row.get("disposition") == "verified" else {field, "disposition", "blocker_code"}
            item = _closed(row, extra, f"STATUS_{group[:-1].upper()}_KEYS", errors)
            if item is None or item["disposition"] not in dispositions or item["blocker_code"] not in {None, "EVIDENCE_NOT_RECORDED"}: _add(errors, f"STATUS_{group[:-1].upper()}_VALUE")
            if group == "gates" and item and item["disposition"] == "verified":
                proof = item["provenance"]
                if item["blocker_code"] is not None or item["evidence_ref"] not in evidence or not _closed(proof, {"subject_sha256", "predicate_sha256"}, "STATUS_PROVENANCE", errors) or not all(is_sha256(proof[key]) for key in ("subject_sha256", "predicate_sha256")):
                    _add(errors, f"STATUS_UNTRUSTED_EVIDENCE:{item['gate_id']}")
                if any(word in str(item["evidence_ref"]).lower() for word in ("compile", "stub", "synthetic")):
                    _add(errors, f"STATUS_UNTRUSTED_EVIDENCE:{item['gate_id']}")
                else: verified_refs.append(item["evidence_ref"])
    if len(verified_refs) != len(set(verified_refs)): _add(errors, f"STATUS_REUSED_EVIDENCE:{next(ref for ref in verified_refs if verified_refs.count(ref) > 1)}")
    return tuple(sorted(set(errors)))


def validate_repository(root: Path, *, verify_source_ref: str | None = None, status_path: Path | None = None) -> tuple[str, ...]:
    """Validate the definition and one selected status/evidence wave on disk."""

    profile = root / "docs/profiles/desktop-v1-capabilities-v1.json"; selected = status_path or root / "docs/evidence/desktop-v1-capability-status-v1.json"; errors: list[str] = []
    try:
        definition = load_json(profile); status = load_json(selected)
        if not has_raw_sha256(profile.read_bytes(), profile.with_suffix(".digest").read_text(encoding="utf-8")): _add(errors, "DEFINITION_RAW_DIGEST_MISMATCH")
        requirements = registry_ids(root / "docs/desktop/00-foundation/REQUIREMENTS.md", "REQ-"); abuse = registry_ids(root / "docs/desktop/07-testing/SECURITY_ABUSE_CASES.md", "SA-")
        errors.extend(validate_definition(definition, requirements, abuse))
        if isinstance(definition, Mapping): errors.extend(validate_status(definition, status))
        else: _add(errors, "DEFINITION_KEYS")
        if not isinstance(status, dict) or status.get("definition_sha256") != sha256_file(profile): _add(errors, "STATUS_DEFINITION_DIGEST_MISMATCH")
        bundle = root / "contracts/gocode-ui-client-1/bundle.json"; sidecar = root / "contracts/gocode-ui-client-1/bundle.sha256"; digest = sha256_file(bundle)
        if sidecar.read_text(encoding="utf-8").strip() != digest or not isinstance(status, dict) or not isinstance(status.get("contract"), dict) or status["contract"].get("profile_sha256") != digest or status["contract"].get("bundle_sha256") != digest: _add(errors, "STATUS_CONTRACT_WAVE_MISMATCH")
        for row in status.get("evidence_refs", []) if isinstance(status, dict) else []:
            path = selected.parent / row.get("id", "") if isinstance(row, dict) else None
            if not isinstance(path, Path) or path.parent != selected.parent or not path.is_file() or row.get("sha256") != sha256_file(path): _add(errors, "EVIDENCE_DIGEST_MISMATCH")
        if verify_source_ref is not None:
            commit = resolve_commit(root, verify_source_ref)
            if not clean_source_paths(root): _add(errors, "SOURCE_PATHS_DIRTY")
            if not isinstance(status, dict) or status.get("canonical_source_content_sha256") != canonical_source_content_digest(root, commit): _add(errors, "SOURCE_CONTENT_DIGEST_MISMATCH")
    except (CalledProcessError, OSError, ValueError): _add(errors, "REPOSITORY_READ_ERROR")
    return tuple(sorted(set(errors)))
