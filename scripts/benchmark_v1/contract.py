"""Strict, offline validation for Benchmark V1 artifacts."""

from __future__ import annotations

import hashlib
import pathlib
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from .validation import (
    ContractError,
    choice as _choice,
    integer as _integer,
    load_verified_json,
    object_exact as _object,
    text as _text,
)


DIGEST = re.compile(r"^[0-9a-f]{64}$")
SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
FROZEN_AT = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
JOURNEYS = {
    "pr_ready_bug_fix",
    "dependency_security_upgrade",
    "bounded_refactor",
}
FLOATING_REVISIONS = {"dev", "head", "latest", "main", "master"}
OUTCOMES = {"Verified", "Unverified", "Uncertain", "Failed"}


@dataclass(frozen=True)
class BenchmarkProfile:
    profile_id: str
    sample_size: int
    eligible_denominator: int
    case_ids: frozenset[str]
    journey_counts: dict[str, int]
    value: dict[str, Any]


def _digest(value: Any, path: str) -> str:
    text = _text(value, path, pattern=DIGEST)
    if text == "0" * 64:
        raise ContractError(f"{path}: zero digest")
    return text


def _is_floating_revision(value: str) -> bool:
    tokens = {token for token in re.split(r"[/._-]+", value.lower()) if token}
    return bool(tokens & FLOATING_REVISIONS)


def _validate_journey(value: Any, path: str) -> str:
    journey = _object(
        value,
        path,
        {
            "schema_version", "journey_id", "revision", "title", "objective",
            "scope", "verifier_contract",
        },
    )
    if journey["schema_version"] != "runne.benchmark.journey/1":
        raise ContractError(f"{path}.schema_version: unsupported value")
    journey_id = _choice(journey["journey_id"], f"{path}.journey_id", JOURNEYS)
    if journey["revision"] != 1:
        raise ContractError(f"{path}.revision: unsupported value")
    _text(journey["title"], f"{path}.title", maximum=80)
    _text(journey["objective"], f"{path}.objective", maximum=500)
    scope = _object(
        journey["scope"],
        f"{path}.scope",
        {"max_files_changed", "max_changed_lines", "network_allowed", "new_dependencies_allowed"},
    )
    for field, maximum in (("max_files_changed", 30), ("max_changed_lines", 2000)):
        if _integer(scope[field], f"{path}.scope.{field}", maximum) == 0:
            raise ContractError(f"{path}.scope.{field}: positive value required")
    if scope["network_allowed"] is not False or not isinstance(scope["new_dependencies_allowed"], bool):
        raise ContractError(f"{path}.scope: invalid policy")
    verifier = _object(
        journey["verifier_contract"],
        f"{path}.verifier_contract",
        {"kind", "requires_clean_exit", "requires_targeted_tests", "requires_diff_check"},
    )
    if verifier != {
        "kind": "machine",
        "requires_clean_exit": True,
        "requires_targeted_tests": True,
        "requires_diff_check": True,
    }:
        raise ContractError(f"{path}.verifier_contract: machine verification required")
    return journey_id


def _validate_case(value: Any, index: int) -> tuple[str, str]:
    path = f"$.cases[{index}]"
    case = _object(
        value,
        path,
        {
            "case_id", "journey_id", "journey_spec_sha256",
            "repository_manifest_sha256", "fixture_manifest_sha256",
            "task_spec_sha256", "verifier_id", "verifier_version",
            "verifier_sha256", "budgets",
        },
    )
    case_id = _text(case["case_id"], f"{path}.case_id", pattern=IDENTIFIER)
    journey = _choice(case["journey_id"], f"{path}.journey_id", JOURNEYS)
    for field in (
        "journey_spec_sha256", "repository_manifest_sha256",
        "fixture_manifest_sha256", "task_spec_sha256", "verifier_sha256",
    ):
        _digest(case[field], f"{path}.{field}")
    _text(case["verifier_id"], f"{path}.verifier_id", pattern=IDENTIFIER)
    revision = _text(case["verifier_version"], f"{path}.verifier_version", pattern=SEMVER)
    if revision.lower() in FLOATING_REVISIONS:
        raise ContractError(f"{path}.verifier_version: floating revision")
    budgets = _object(
        case["budgets"], f"{path}.budgets",
        {"wall_seconds", "input_tokens", "output_tokens", "cost_micros"},
    )
    for field, maximum in (
        ("wall_seconds", 7200), ("input_tokens", 1_000_000),
        ("output_tokens", 1_000_000), ("cost_micros", 1_000_000_000),
    ):
        if _integer(budgets[field], f"{path}.budgets.{field}", maximum) == 0:
            raise ContractError(f"{path}.budgets.{field}: positive value required")
    return case_id, journey


def validate_profile(value: Any) -> BenchmarkProfile:
    profile = _object(
        value,
        "$",
        {
            "schema_version", "contract_id", "profile_id", "frozen_at",
            "source", "execution", "sample_size", "eligible_denominator",
            "stopping_rule", "cases",
        },
    )
    if profile["schema_version"] != "runne.benchmark.profile/1":
        raise ContractError("$.schema_version: unsupported value")
    if profile["contract_id"] != "runne-benchmark-v1":
        raise ContractError("$.contract_id: unsupported value")
    profile_id = _text(profile["profile_id"], "$.profile_id", pattern=IDENTIFIER)
    _text(profile["frozen_at"], "$.frozen_at", pattern=FROZEN_AT)
    source = _object(profile["source"], "$.source", {"repository", "revision", "artifact_sha256"})
    if not _text(source["repository"], "$.source.repository").startswith("https://"):
        raise ContractError("$.source.repository: https URL required")
    _text(source["revision"], "$.source.revision", pattern=SOURCE_REVISION)
    _digest(source["artifact_sha256"], "$.source.artifact_sha256")
    execution = _object(
        profile["execution"], "$.execution",
        {"provider_id", "provider_profile_sha256", "model_id", "model_revision", "runtime_policy_sha256", "tool_policy_sha256", "environment_sha256"},
    )
    _text(execution["provider_id"], "$.execution.provider_id")
    _text(execution["model_id"], "$.execution.model_id")
    model_revision = _text(execution["model_revision"], "$.execution.model_revision")
    if _is_floating_revision(model_revision):
        raise ContractError("$.execution.model_revision: floating revision")
    for field in ("provider_profile_sha256", "runtime_policy_sha256", "tool_policy_sha256", "environment_sha256"):
        _digest(execution[field], f"$.execution.{field}")
    if profile["sample_size"] != 12 or profile["eligible_denominator"] != 12:
        raise ContractError("$: sample and eligible denominator must equal 12")
    if profile["stopping_rule"] != "complete_all_eligible_cases":
        raise ContractError("$.stopping_rule: unsupported value")
    cases = profile["cases"]
    if not isinstance(cases, list) or len(cases) != 12:
        raise ContractError("$.cases: exactly 12 cases required")
    identities = [_validate_case(case, index) for index, case in enumerate(cases)]
    case_ids = [case_id for case_id, _ in identities]
    if len(set(case_ids)) != len(case_ids):
        raise ContractError("$.cases: duplicate case_id")
    counts = Counter(journey for _, journey in identities)
    if counts != Counter({journey: 4 for journey in JOURNEYS}):
        raise ContractError("$.cases: exactly four cases per journey required")
    return BenchmarkProfile(profile_id, 12, 12, frozenset(case_ids), dict(sorted(counts.items())), profile)


def derive_outcome(value: dict[str, Any]) -> str:
    if value.get("effect_state") == "uncertain" or value.get("recovery_state") == "uncertain" or value.get("evidence_complete") is False:
        return "Uncertain"
    if value.get("effect_state") == "failed" or value.get("recovery_state") == "failed" or value.get("execution_status") == "failed" or value.get("verifier_result") == "failed":
        return "Failed"
    if value.get("execution_status") == "completed" and value.get("verifier_result") == "passed" and value.get("effect_state") in {"none", "confirmed"} and value.get("recovery_state") == "clean" and value.get("evidence_complete") is True:
        return "Unverified" if value.get("manual_override") is True else "Verified"
    if value.get("execution_status") == "completed" and value.get("verifier_result") in {"inconclusive", "not_run"}:
        return "Unverified"
    raise ContractError("$: evidence combination has no technical outcome")


def validate_outcome(value: Any, case_ids: set[str] | frozenset[str]) -> dict[str, Any]:
    outcome = _object(value, "$", {"schema_version", "case_id", "technical_outcome", "acceptance", "manual_override", "execution_status", "verifier_result", "effect_state", "recovery_state", "evidence_complete", "timing", "cost"})
    if outcome["schema_version"] != "runne.benchmark.outcome/1":
        raise ContractError("$.schema_version: unsupported value")
    case_id = _text(outcome["case_id"], "$.case_id", pattern=IDENTIFIER)
    if case_id not in case_ids:
        raise ContractError("$.case_id: not in frozen profile")
    _choice(outcome["technical_outcome"], "$.technical_outcome", OUTCOMES)
    _choice(outcome["acceptance"], "$.acceptance", {"Accepted", "Rejected", "Pending", "NotApplicable"})
    if not isinstance(outcome["manual_override"], bool) or not isinstance(outcome["evidence_complete"], bool):
        raise ContractError("$: boolean evidence fields required")
    _choice(outcome["execution_status"], "$.execution_status", {"completed", "failed"})
    _choice(outcome["verifier_result"], "$.verifier_result", {"passed", "failed", "inconclusive", "not_run"})
    _choice(outcome["effect_state"], "$.effect_state", {"none", "confirmed", "uncertain", "failed"})
    _choice(outcome["recovery_state"], "$.recovery_state", {"clean", "uncertain", "failed"})
    timing = _object(outcome["timing"], "$.timing", {"task_seconds", "review_minutes", "recovery_minutes"})
    for field, maximum in (("task_seconds", 86400), ("review_minutes", 1440), ("recovery_minutes", 1440)):
        _integer(timing[field], f"$.timing.{field}", maximum)
    cost = _object(outcome["cost"], "$.cost", {"currency", "model_compute_micros", "human_review_micros", "recovery_micros"})
    if cost["currency"] != "USD":
        raise ContractError("$.cost.currency: unsupported value")
    for field in ("model_compute_micros", "human_review_micros", "recovery_micros"):
        _integer(cost[field], f"$.cost.{field}", 1_000_000_000)
    derived = derive_outcome(outcome)
    if outcome["technical_outcome"] != derived:
        raise ContractError("$.technical_outcome: declared outcome does not match evidence")
    return outcome


def validate_cohort_envelope(value: Any, profile_sha256: str) -> list[dict[str, Any]]:
    cohort = _object(value, "$", {"schema_version", "profile_sha256", "outcomes"})
    if cohort["schema_version"] != "runne.benchmark.cohort/1":
        raise ContractError("$.schema_version: unsupported value")
    if _digest(cohort["profile_sha256"], "$.profile_sha256") != profile_sha256:
        raise ContractError("$.profile_sha256: frozen profile digest mismatch")
    if not isinstance(cohort["outcomes"], list):
        raise ContractError("$.outcomes: array required")
    return cohort["outcomes"]


def verify_contract(root: pathlib.Path) -> dict[str, Any]:
    benchmark = root / "docs/benchmarks/v1"
    schemas = root / "docs/schemas"
    for name in ("journey", "profile", "outcome"):
        schema = load_verified_json(schemas / f"benchmark-{name}-v1.schema.json")
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" or schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            raise ContractError(f"benchmark-{name}-v1.schema.json: open schema")
    journey_digests: dict[str, str] = {}
    for path in sorted((benchmark / "journeys").glob("*.json")):
        journey = load_verified_json(path)
        journey_id = _validate_journey(journey, path.name)
        if journey_id in journey_digests:
            raise ContractError("journeys: duplicate journey_id")
        journey_digests[journey_id] = hashlib.sha256(path.read_bytes()).hexdigest()
    if set(journey_digests) != JOURNEYS:
        raise ContractError("journeys: exact three specs required")
    profile_path = benchmark / "benchmark-profile-v1.json"
    profile = validate_profile(load_verified_json(profile_path))
    for case in profile.value["cases"]:
        if case["journey_spec_sha256"] != journey_digests[case["journey_id"]]:
            raise ContractError(f"{case['case_id']}: journey digest mismatch")
    valid = 0
    for name in ("verified", "unverified", "uncertain", "failed"):
        validate_outcome(load_verified_json(benchmark / "fixtures" / f"outcome-{name}-v1.json"), profile.case_ids)
        valid += 1
    malformed = load_verified_json(benchmark / "fixtures/outcome-malformed-v1.json")
    try:
        validate_outcome(malformed, profile.case_ids)
    except ContractError:
        rejected = 1
    else:
        raise ContractError("malformed outcome fixture was accepted")
    cohort = load_verified_json(benchmark / "fixtures/complete-cohort-v1.json")
    outcomes = validate_cohort_envelope(
        cohort,
        hashlib.sha256(profile_path.read_bytes()).hexdigest(),
    )
    from .aggregate import summarize

    summary = summarize(profile, outcomes)
    return {
        "contract_id": "runne-benchmark-v1",
        "journeys": 3,
        "eligible_cases": 12,
        "valid_outcome_fixtures": valid,
        "malformed_fixtures_rejected": rejected,
        "cohort_outcomes": len(outcomes),
        "cohort_counts": summary["counts"],
    }
