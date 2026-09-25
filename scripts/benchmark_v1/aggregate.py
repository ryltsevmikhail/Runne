"""Deterministic Benchmark V1 aggregate computation."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from .contract import BenchmarkProfile, ContractError, validate_outcome


def _nearest_rank(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def summarize(profile: BenchmarkProfile, outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(outcomes, list):
        raise ContractError("$.outcomes: array required")
    validated: dict[str, dict[str, Any]] = {}
    for value in outcomes:
        outcome = validate_outcome(value, profile)
        case_id = outcome["case_id"]
        if case_id in validated:
            raise ContractError("$.outcomes: duplicate outcome")
        validated[case_id] = outcome
    if set(validated) != set(profile.case_ids):
        raise ContractError("$.outcomes: complete frozen cohort required")
    ordered = [validated[case_id] for case_id in sorted(validated)]
    counts = Counter(item["technical_outcome"] for item in ordered)
    verified = [item for item in ordered if item["technical_outcome"] == "Verified"]
    cost_components = {
        "human_review": sum(item["cost"]["human_review_micros"] for item in verified),
        "model_compute": sum(item["cost"]["model_compute_micros"] for item in verified),
        "recovery": sum(item["cost"]["recovery_micros"] for item in verified),
    }
    cost_total = sum(cost_components.values())
    ttvo = [item["timing"]["task_seconds"] for item in verified]
    return {
        "schema_version": "runne.benchmark.summary/1",
        "profile_id": profile.profile_id,
        "eligible_denominator": profile.eligible_denominator,
        "counts": {name: counts.get(name, 0) for name in ("Failed", "Uncertain", "Unverified", "Verified")},
        "vcr": {"numerator": len(verified), "denominator": profile.eligible_denominator},
        "wavo_count": sum(item["acceptance"] == "Accepted" and not item["manual_override"] for item in verified),
        "ttvo_seconds": (
            {"p50": _nearest_rank(ttvo, 0.5), "p90": _nearest_rank(ttvo, 0.9)}
            if verified
            else None
        ),
        "cpvo_micros": (
            {
                "denominator": len(verified),
                "components": cost_components,
                "total_numerator": cost_total,
            }
            if verified
            else None
        ),
        "human_intervention_minutes": {
            "review": sum(item["timing"]["review_minutes"] for item in ordered),
            "recovery": sum(item["timing"]["recovery_minutes"] for item in ordered),
        },
        "recovery_cases": sum(item["recovery_state"] != "clean" for item in ordered),
        "uncertain_cases": counts.get("Uncertain", 0),
    }
