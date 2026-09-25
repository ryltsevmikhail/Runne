"""Exact machine-verification boundaries for Benchmark V1 journeys."""

from __future__ import annotations

from typing import Any

from .validation import ContractError, choice, integer, object_exact, text


JOURNEY_CHECKS = {
    "pr_ready_bug_fix": [
        "reproduction_before",
        "targeted_regression_after",
        "required_tests_pass",
        "diff_within_scope",
    ],
    "dependency_security_upgrade": [
        "vulnerable_state_before",
        "remediation_version_pinned",
        "advisory_check_after",
        "locked_build_pass",
        "required_tests_pass",
        "diff_within_scope",
    ],
    "bounded_refactor": [
        "characterization_before",
        "characterization_after",
        "observable_behavior_equivalent",
        "required_tests_pass",
        "diff_within_scope",
    ],
}
JOURNEYS = set(JOURNEY_CHECKS)
SUCCESS_CONDITIONS = [
    "all_required_checks_pass",
    "process_exit_zero",
    "diff_within_declared_scope",
    "no_unresolved_effect",
]
FAILURE_CONDITIONS = [
    "required_check_failed",
    "process_exit_nonzero",
    "scope_exceeded",
    "effect_or_recovery_failed",
]


def validate_journey(value: Any, path: str) -> str:
    journey = object_exact(
        value,
        path,
        {
            "schema_version", "journey_id", "revision", "title", "objective",
            "scope", "verifier_contract", "required_checks",
            "success_conditions", "failure_conditions",
        },
    )
    if journey["schema_version"] != "runne.benchmark.journey/1":
        raise ContractError(f"{path}.schema_version: unsupported value")
    journey_id = choice(journey["journey_id"], f"{path}.journey_id", JOURNEYS)
    if journey["revision"] != 1:
        raise ContractError(f"{path}.revision: unsupported value")
    text(journey["title"], f"{path}.title", maximum=80)
    text(journey["objective"], f"{path}.objective", maximum=500)
    scope = object_exact(
        journey["scope"],
        f"{path}.scope",
        {"max_files_changed", "max_changed_lines", "network_allowed", "new_dependencies_allowed"},
    )
    for field, maximum in (("max_files_changed", 30), ("max_changed_lines", 2000)):
        if integer(scope[field], f"{path}.scope.{field}", maximum) == 0:
            raise ContractError(f"{path}.scope.{field}: positive value required")
    if scope["network_allowed"] is not False or not isinstance(scope["new_dependencies_allowed"], bool):
        raise ContractError(f"{path}.scope: invalid policy")
    verifier = object_exact(
        journey["verifier_contract"],
        f"{path}.verifier_contract",
        {"kind", "requires_clean_exit", "requires_targeted_tests", "requires_diff_check"},
    )
    expected_verifier = {
        "kind": "machine",
        "requires_clean_exit": True,
        "requires_targeted_tests": True,
        "requires_diff_check": True,
    }
    if verifier != expected_verifier:
        raise ContractError(f"{path}.verifier_contract: machine verification required")
    if journey["required_checks"] != JOURNEY_CHECKS[journey_id]:
        raise ContractError(f"{path}.required_checks: exact journey checks required")
    if journey["success_conditions"] != SUCCESS_CONDITIONS:
        raise ContractError(f"{path}.success_conditions: exact success boundary required")
    if journey["failure_conditions"] != FAILURE_CONDITIONS:
        raise ContractError(f"{path}.failure_conditions: exact failure boundary required")
    return journey_id
