import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from scripts.benchmark_v1.aggregate import summarize
from scripts.benchmark_v1.contract import (
    ContractError,
    derive_outcome,
    load_verified_json,
    validate_cohort_envelope,
    validate_outcome,
    validate_profile,
    verify_contract,
)


ROOT = pathlib.Path(__file__).parents[2]
BENCHMARK = ROOT / "docs/benchmarks/v1"
PROFILE_PATH = BENCHMARK / "benchmark-profile-v1.json"
FIXTURES = BENCHMARK / "fixtures"


def fixture(name: str) -> dict:
    return load_verified_json(FIXTURES / name)


class BenchmarkV1ContractTests(unittest.TestCase):
    def test_profile_freezes_exact_twelve_cases_four_per_journey(self) -> None:
        profile = validate_profile(load_verified_json(PROFILE_PATH))

        self.assertEqual(profile.sample_size, 12)
        self.assertEqual(profile.eligible_denominator, 12)
        self.assertEqual(
            profile.journey_counts,
            {
                "bounded_refactor": 4,
                "dependency_security_upgrade": 4,
                "pr_ready_bug_fix": 4,
            },
        )

    def test_profile_rejects_duplicate_cases_and_floating_revisions(self) -> None:
        value = load_verified_json(PROFILE_PATH)
        duplicate = copy.deepcopy(value)
        duplicate["cases"][1]["case_id"] = duplicate["cases"][0]["case_id"]
        with self.assertRaisesRegex(ContractError, "duplicate case_id"):
            validate_profile(duplicate)

        floating = copy.deepcopy(value)
        floating["execution"]["model_revision"] = "latest"
        with self.assertRaisesRegex(ContractError, "floating revision"):
            validate_profile(floating)

        embedded = copy.deepcopy(value)
        embedded["execution"]["model_revision"] = "refs/heads/main"
        with self.assertRaisesRegex(ContractError, "floating revision"):
            validate_profile(embedded)

        invalid_time = copy.deepcopy(value)
        invalid_time["frozen_at"] = "today"
        with self.assertRaisesRegex(ContractError, "invalid format"):
            validate_profile(invalid_time)

    def test_four_outcomes_are_derived_and_declared_value_must_match(self) -> None:
        expected = {
            "outcome-verified-v1.json": "Verified",
            "outcome-unverified-v1.json": "Unverified",
            "outcome-uncertain-v1.json": "Uncertain",
            "outcome-failed-v1.json": "Failed",
        }
        for name, outcome in expected.items():
            value = fixture(name)
            self.assertEqual(derive_outcome(value), outcome, name)
            self.assertEqual(
                validate_outcome(value, {value["case_id"]})["technical_outcome"],
                outcome,
            )

        malformed = fixture("outcome-malformed-v1.json")
        with self.assertRaisesRegex(ContractError, "declared outcome"):
            validate_outcome(malformed, {malformed["case_id"]})

    def test_manual_override_never_derives_verified(self) -> None:
        value = fixture("outcome-verified-v1.json")
        value["manual_override"] = True
        value["technical_outcome"] = "Unverified"

        self.assertEqual(derive_outcome(value), "Unverified")

    def test_complete_cohort_summary_is_exact_and_order_independent(self) -> None:
        profile = validate_profile(load_verified_json(PROFILE_PATH))
        cohort = fixture("complete-cohort-v1.json")
        expected = {
            "schema_version": "runne.benchmark.summary/1",
            "profile_id": "runne-benchmark-v1-contract-fixture",
            "eligible_denominator": 12,
            "counts": {
                "Failed": 3,
                "Uncertain": 3,
                "Unverified": 3,
                "Verified": 3,
            },
            "vcr": {"numerator": 3, "denominator": 12},
            "wavo_count": 2,
            "ttvo_seconds": {"p50": 200, "p90": 300},
            "cpvo_micros": {
                "denominator": 3,
                "components": {
                    "human_review": 300,
                    "model_compute": 600,
                    "recovery": 50,
                },
                "total_numerator": 950,
            },
            "human_intervention_minutes": {"review": 90, "recovery": 23},
            "recovery_cases": 2,
            "uncertain_cases": 3,
        }

        self.assertEqual(summarize(profile, cohort["outcomes"]), expected)
        self.assertEqual(summarize(profile, list(reversed(cohort["outcomes"]))), expected)

    def test_zero_verified_has_null_time_and_cost_metrics(self) -> None:
        profile = validate_profile(load_verified_json(PROFILE_PATH))
        template = fixture("outcome-unverified-v1.json")
        outcomes = []
        for case_id in sorted(profile.case_ids):
            outcome = copy.deepcopy(template)
            outcome["case_id"] = case_id
            outcomes.append(outcome)

        result = summarize(profile, outcomes)

        self.assertEqual(result["vcr"], {"numerator": 0, "denominator": 12})
        self.assertIsNone(result["ttvo_seconds"])
        self.assertIsNone(result["cpvo_micros"])

    def test_missing_or_duplicate_outcome_blocks_summary(self) -> None:
        profile = validate_profile(load_verified_json(PROFILE_PATH))
        outcomes = fixture("complete-cohort-v1.json")["outcomes"]
        with self.assertRaisesRegex(ContractError, "complete frozen cohort"):
            summarize(profile, outcomes[:-1])
        duplicate = copy.deepcopy(outcomes)
        duplicate[-1]["case_id"] = duplicate[0]["case_id"]
        with self.assertRaisesRegex(ContractError, "duplicate outcome"):
            summarize(profile, duplicate)

    def test_sidecar_mismatch_and_duplicate_json_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "value.json"
            path.write_text('{"a":1,"a":2}\n', encoding="utf-8")
            path.with_suffix(".json.sha256").write_text(
                f"{'0' * 64}  value.json\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ContractError, "digest mismatch"):
                load_verified_json(path)
            path.with_suffix(".json.sha256").unlink()
            with self.assertRaisesRegex(ContractError, "duplicate JSON key"):
                load_verified_json(path, require_sidecar=False)

    def test_contract_verifier_checks_schemas_journeys_and_fixtures(self) -> None:
        result = verify_contract(ROOT)

        self.assertEqual(result["contract_id"], "runne-benchmark-v1")
        self.assertEqual(result["journeys"], 3)
        self.assertEqual(result["eligible_cases"], 12)
        self.assertEqual(result["valid_outcome_fixtures"], 4)
        self.assertEqual(result["malformed_fixtures_rejected"], 1)
        self.assertEqual(result["cohort_outcomes"], 12)

    def test_cohort_is_bound_to_exact_profile_bytes(self) -> None:
        cohort = fixture("complete-cohort-v1.json")
        digest = hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest()
        self.assertEqual(len(validate_cohort_envelope(cohort, digest)), 12)

        cohort["profile_sha256"] = "1" * 64
        with self.assertRaisesRegex(ContractError, "profile digest mismatch"):
            validate_cohort_envelope(cohort, digest)

    def test_cli_emits_canonical_json_for_verify_and_summary(self) -> None:
        script = ROOT / "scripts/verify-benchmark-v1.py"
        verify = subprocess.run(
            [sys.executable, str(script), "verify-contract", "--root", str(ROOT)],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(verify.stdout)
        self.assertEqual(result["eligible_cases"], 12)
        self.assertEqual(verify.stdout, json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")

        summary = subprocess.run(
            [
                sys.executable,
                str(script),
                "summarize",
                "--profile",
                str(PROFILE_PATH),
                "--outcomes",
                str(FIXTURES / "complete-cohort-v1.json"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(json.loads(summary.stdout)["vcr"], {"denominator": 12, "numerator": 3})


if __name__ == "__main__":
    unittest.main()
