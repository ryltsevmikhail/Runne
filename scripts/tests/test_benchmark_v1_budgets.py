import copy
import pathlib
import unittest

from scripts.benchmark_v1.contract import (
    ContractError,
    load_verified_json,
    validate_outcome,
    validate_profile,
)


ROOT = pathlib.Path(__file__).parents[2]
BENCHMARK = ROOT / "docs/benchmarks/v1"
PROFILE = BENCHMARK / "benchmark-profile-v1.json"
VERIFIED = BENCHMARK / "fixtures/outcome-verified-v1.json"


class BenchmarkV1BudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = validate_profile(load_verified_json(PROFILE))
        self.verified = load_verified_json(VERIFIED)

    def test_time_budget_breach_is_failed_not_verified(self) -> None:
        outcome = copy.deepcopy(self.verified)
        outcome["timing"]["task_seconds"] = 1801
        with self.assertRaisesRegex(ContractError, "declared outcome"):
            validate_outcome(outcome, self.profile)

        outcome["technical_outcome"] = "Failed"
        self.assertEqual(
            validate_outcome(outcome, self.profile)["technical_outcome"],
            "Failed",
        )

    def test_token_and_total_cost_breaches_are_failed(self) -> None:
        for mutate in (
            lambda value: value["usage"].update(input_tokens=200001),
            lambda value: value["usage"].update(output_tokens=20001),
            lambda value: value["cost"].update(model_compute_micros=2_000_001),
        ):
            with self.subTest(mutate=mutate):
                outcome = copy.deepcopy(self.verified)
                mutate(outcome)
                with self.assertRaisesRegex(ContractError, "declared outcome"):
                    validate_outcome(outcome, self.profile)

    def test_exact_budget_boundary_remains_verified(self) -> None:
        outcome = copy.deepcopy(self.verified)
        outcome["timing"]["task_seconds"] = 1800
        outcome["usage"] = {"input_tokens": 200000, "output_tokens": 20000}
        outcome["cost"] = {
            "currency": "USD",
            "model_compute_micros": 1_500_000,
            "human_review_micros": 400_000,
            "recovery_micros": 100_000,
        }
        self.assertEqual(
            validate_outcome(outcome, self.profile)["technical_outcome"],
            "Verified",
        )


if __name__ == "__main__":
    unittest.main()
