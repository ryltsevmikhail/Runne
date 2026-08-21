"""Cross-record binding diagnostics for local RC0 fixtures only."""

from __future__ import annotations

from typing import Any, Mapping

from .rules import (
    BINDING_FIELDS,
    BLOCKED_REASONS,
    SUPPORTED_STAGES,
    UNSUPPORTED_STAGES,
    validate_artifact_bijection,
    validate_content_locator,
    validate_policy_inventory,
    validate_portable_relative_path,
    validate_source_capture,
)

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
SUPPORTED_EVIDENCE_PROFILES = frozenset(
    ("gocode.rc0.evidence-profile/3", "gocode.rc0.evidence-profile/4")
)


def validate_stage_dispositions(records: list[Mapping[str, Any]]) -> tuple[str, ...]:
    errors: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            errors.append(f"[{index}]: stage disposition must be an object")
            continue
        stage = record.get("stage")
        if stage in UNSUPPORTED_STAGES:
            if record.get("report_stage_disposition") != "OUT_OF_SCOPE":
                errors.append(f"[{index}]: unsupported stage must be OUT_OF_SCOPE")
            if set(record) != {"stage", "report_stage_disposition"}:
                errors.append(f"[{index}]: unsupported stage cannot carry a gate result or outcome")
        elif stage in SUPPORTED_STAGES:
            if "report_stage_disposition" in record:
                errors.append(f"[{index}]: supported stage cannot be OUT_OF_SCOPE")
        else:
            errors.append(f"[{index}]: unknown stage")
    return tuple(errors)


def _validate_aggregate(record: Any, expected: str, reason: str | None, label: str) -> list[str]:
    if not isinstance(record, dict):
        return [f"{label} aggregate is missing"]
    errors: list[str] = []
    if record.get("gate_result") != expected:
        errors.append(f"{label} aggregate result is inconsistent")
    actual_reason = record.get("blocked_reason")
    if expected == "PASS" and actual_reason is not None:
        errors.append(f"{label} PASS aggregate cannot have a blocked reason")
    if expected == "BLOCKED" and (actual_reason != reason or not isinstance(actual_reason, str) or actual_reason not in BLOCKED_REASONS):
        errors.append(f"{label} aggregate blocked reason is not exact")
    return errors


def _validate_report_artifacts(artifacts: Any, candidate_source_sha: Any) -> list[str]:
    if not isinstance(artifacts, list) or not artifacts:
        return ["report exact_artifact_bindings must be non-vacuous"]
    errors: list[str] = []
    keys: list[tuple[Any, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("report artifact binding must be an object")
            continue
        errors.extend(validate_portable_relative_path(artifact.get("relative_path")))
        locator = artifact.get("locator")
        errors.extend(validate_content_locator(locator))
        if isinstance(locator, str) and locator.startswith("cas:sha256:") and locator.removeprefix("cas:sha256:") != artifact.get("sha256"):
            errors.append("report locator digest does not bind artifact sha256")
        if isinstance(locator, str) and locator.startswith("git:") and locator.split(":", 2)[1] != candidate_source_sha:
            errors.append("report Git locator does not bind candidate source")
        path, digest = artifact.get("relative_path"), artifact.get("sha256")
        if isinstance(path, str) and isinstance(digest, str):
            keys.append((path, digest))
        else:
            errors.append("report artifact key is malformed")
    if len(keys) != len(set(keys)):
        errors.append("report artifact keys must be unique")
    paths = [key[0] for key in keys if isinstance(key[0], str)]
    if paths != sorted(paths, key=lambda value: value.encode("utf-8")):
        errors.append("report artifacts must use canonical UTF-8 path order")
    return errors


def validate_report_against_policy(
    report: Mapping[str, Any], policy: Mapping[str, Any], expected_binding: Mapping[str, Any]
) -> tuple[str, ...]:
    """Validate supplied report-shaped fixture data without issuing a report."""
    errors = [f"policy: {item}" for item in validate_policy_inventory(policy)]
    expected = {field: expected_binding.get(field) for field in BINDING_FIELDS}
    if set(expected_binding) != set(BINDING_FIELDS) or any(value is None for value in expected.values()):
        errors.append("expected common qualification binding is incomplete")
    actual = {field: report.get(field) for field in BINDING_FIELDS}
    if actual != expected:
        errors.append("report common qualification binding is incomplete or mismatched")
    if report.get("policy_revision") != policy.get("policy_revision") or report.get("policy_digest") != policy.get("policy_digest"):
        errors.append("report does not bind the supplied policy revision and digest")
    errors.extend(_validate_report_artifacts(report.get("exact_artifact_bindings"), report.get("candidate_source_sha")))

    raw_policy_gates = policy.get("required_gates", [])
    if not isinstance(raw_policy_gates, list):
        raw_policy_gates = []
    policy_gates = {
        gate.get("gate_id"): gate
        for gate in raw_policy_gates
        if isinstance(gate, dict) and isinstance(gate.get("gate_id"), str)
    }
    results = report.get("required_gate_results", [])
    if not isinstance(results, list):
        results = []
        errors.append("REQUIRED_GATE_MISMATCH: required_gate_results must be an array")
    result_ids = [item.get("gate_id") for item in results if isinstance(item, dict) and isinstance(item.get("gate_id"), str)]
    exact_results = len(result_ids) == len(policy_gates) and len(set(result_ids)) == len(result_ids) and set(result_ids) == set(policy_gates)
    if not exact_results:
        errors.append("REQUIRED_GATE_MISMATCH: report must contain each policy gate exactly once")

    stage_state: dict[str, list[tuple[str, str | None]]] = {stage: [] for stage in SUPPORTED_STAGES}
    mapping = {
        "PASS": ("PASS", None),
        "FAIL": ("BLOCKED", "REQUIRED_GATE_FAILED"),
        "NOT_RUN": ("BLOCKED", "REQUIRED_GATE_NOT_RUN"),
    }
    for result in results:
        if not isinstance(result, dict):
            errors.append("required gate result must be an object")
            continue
        gate_id = result.get("gate_id")
        gate = policy_gates.get(gate_id) if isinstance(gate_id, str) else None
        if gate is None or result.get("stage") != gate.get("stage"):
            errors.append("REQUIRED_GATE_MISMATCH: gate ID/stage is absent from policy")
        expected_outcome = mapping.get(result.get("execution_outcome"))
        actual_outcome = (result.get("gate_result"), result.get("blocked_reason"))
        if expected_outcome != actual_outcome:
            errors.append("required gate mapping or REQUIRED_GATE_* blocked reason is inconsistent")
        result_binding = result.get("binding")
        if not isinstance(result_binding, dict) or set(result_binding) != set(BINDING_FIELDS) or result_binding != expected:
            errors.append("required gate result has an incomplete common binding")
        stage = result.get("stage")
        if isinstance(stage, str) and stage in stage_state and expected_outcome is not None:
            stage_state[stage].append(expected_outcome)

    aggregates: dict[str, tuple[str, str | None]] = {}
    labels = {
        "SOURCE_CANDIDATE": "source_candidate_gate",
        "PRODUCTION_QUALIFICATION": "production_qualification_gate",
    }
    for stage, label in labels.items():
        outcomes = stage_state[stage]
        if not outcomes or not exact_results:
            expected_state = ("BLOCKED", "REQUIRED_GATE_MISMATCH")
        elif all(outcome[0] == "PASS" for outcome in outcomes):
            expected_state = ("PASS", None)
        else:
            expected_state = next(outcome for outcome in outcomes if outcome[0] == "BLOCKED")
        aggregates[label] = expected_state
        errors.extend(_validate_aggregate(report.get(label), *expected_state, label))

    evidence = report.get("evidence_seal_gate")
    if isinstance(evidence, dict) and evidence.get("gate_result") == "PASS":
        evidence_state = ("PASS", None)
    else:
        evidence_reason = evidence.get("blocked_reason") if isinstance(evidence, dict) else None
        evidence_state = ("BLOCKED", evidence_reason)
        if not isinstance(evidence_reason, str) or evidence_reason not in {
            "REQUIRED_GATE_EVIDENCE_UNAVAILABLE",
            "REQUIRED_GATE_POLICY_UNAVAILABLE",
            "REQUIRED_GATE_AUTHORITY_UNAVAILABLE",
        }:
            errors.append("evidence seal uses an inexact REQUIRED_GATE_* unavailable reason")
    errors.extend(_validate_aggregate(evidence, *evidence_state, "evidence_seal_gate"))
    constituent = [*aggregates.values(), evidence_state]
    overall = ("PASS", None) if all(item[0] == "PASS" for item in constituent) else next(item for item in constituent if item[0] == "BLOCKED")
    errors.extend(_validate_aggregate(report.get("overall_candidate_gate"), *overall, "overall_candidate_gate"))

    dispositions = report.get("stage_dispositions", [])
    errors.extend(validate_stage_dispositions(dispositions))
    disposition_stages = [item.get("stage") for item in dispositions if isinstance(item, dict)]
    if len(disposition_stages) != 2 or set(disposition_stages) != set(UNSUPPORTED_STAGES):
        errors.append("report must contain each unsupported OUT_OF_SCOPE stage exactly once")
    return tuple(errors)


def validate_common_bindings(records: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    fields = ("repository_id", "candidate_source_revision", "evidence_attempt_id", "policy_digest")
    errors: list[str] = []
    for field in fields:
        values = [record.get(field) for record in records.values() if isinstance(record, Mapping)]
        if not values or any(value is None for value in values) or any(value != values[0] for value in values[1:]):
            errors.append(f"cross-record binding mismatch: {field}")
    return tuple(errors)


def validate_record_bindings(
    records: Mapping[str, Mapping[str, Any]],
    policy: Mapping[str, Any] | None = None,
    expected_binding: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    evidence = {name: records[name] for name in EVIDENCE_FILES if name in records}
    errors: list[str] = []
    if set(evidence) != set(EVIDENCE_FILES):
        errors.append("normalized evidence requires exactly nine named records")
    errors.extend(validate_common_bindings(evidence))
    json_records = {
        name: record for name, record in evidence.items()
        if name != "checksums.txt" and isinstance(record, Mapping)
    }
    profiles = {record.get("profile") for record in json_records.values()}
    if len(json_records) != len(EVIDENCE_FILES) - 1 or any(
        "profile" not in record for record in json_records.values()
    ) or len(profiles) != 1 or None in profiles or not profiles <= SUPPORTED_EVIDENCE_PROFILES:
        errors.append("cross-record binding mismatch: profile")
    profile = next(iter(profiles), None)
    candidate = evidence.get("candidate-record.json", {})
    source_sha = candidate.get("candidate_source_revision")
    source = evidence.get("source-gate-results.json", {}).get("capture", {})
    if source:
        errors.extend(validate_source_capture(source, source_sha, profile))
    tests = evidence.get("test-inventory.json", {}).get("tests", [])
    if any(test.get("source_sha") != source_sha for test in tests):
        errors.append("test inventory source_sha does not bind candidate source")
    artifact, checksums, spdx = (evidence.get(name) for name in ("artifact-inventory.json", "checksums.txt", "sbom.spdx.json"))
    if artifact is not None and checksums is not None and spdx is not None:
        errors.extend(validate_artifact_bijection(artifact, checksums, spdx))
    report = records.get("verification-report.json")
    if report is not None:
        mapping = {"PASS": "PASS", "FAIL": "BLOCKED", "NOT_RUN": "BLOCKED"}
        raw_results = report.get("required_gate_results", [])
        if not isinstance(raw_results, list) or any(
            not isinstance(item, Mapping)
            or mapping.get(item.get("execution_outcome")) != item.get("gate_result")
            for item in raw_results
        ):
            errors.append("required gate mapping is inconsistent")
        if policy is None or expected_binding is None:
            errors.append("external report fixture requires supplied policy and complete binding")
        else:
            evidence_binding = {
                "repository_id": candidate.get("repository_id"),
                "candidate_source_sha": source_sha,
                "evidence_attempt_id": candidate.get("evidence_attempt_id"),
                "policy_digest": candidate.get("policy_digest"),
                "profile": candidate.get("profile"),
                "exact_artifact_bindings": [
                    {key: item.get(key) for key in ("relative_path", "sha256", "size", "locator")}
                    for item in (artifact or {}).get("artifacts", [])
                ],
            }
            if any(expected_binding.get(field) != value for field, value in evidence_binding.items()):
                errors.append("external report artifact or evidence identity binding mismatch")
            errors.extend(validate_report_against_policy(report, policy, expected_binding))
    return tuple(errors)
