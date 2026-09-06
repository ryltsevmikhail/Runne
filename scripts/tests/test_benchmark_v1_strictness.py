import copy
import hashlib
import pathlib
import shutil
import tempfile
import unittest

from scripts.benchmark_v1.contract import (
    ContractError,
    load_verified_json,
    validate_profile,
    verify_contract,
)


ROOT = pathlib.Path(__file__).parents[2]
PROFILE = ROOT / "docs/benchmarks/v1/benchmark-profile-v1.json"


class BenchmarkV1StrictnessTests(unittest.TestCase):
    def test_profile_scalar_constraints_match_schema(self) -> None:
        value = load_verified_json(PROFILE)
        mutations = (
            ("invalid timestamp", lambda item: item.update(frozen_at="2026-99-99T99:99:99Z")),
            ("provider id", lambda item: item["execution"].update(provider_id="INVALID PROVIDER!")),
            ("model id", lambda item: item["execution"].update(model_id="m" * 129)),
            ("model revision", lambda item: item["execution"].update(model_revision="r" * 129)),
        )
        for reason, mutate in mutations:
            with self.subTest(reason=reason):
                candidate = copy.deepcopy(value)
                mutate(candidate)
                with self.assertRaises(ContractError):
                    validate_profile(candidate)

    def test_non_finite_json_constants_fail_closed(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "payload.json"
                path.write_text(f'{{"value":{constant}}}\n', encoding="utf-8")
                with self.assertRaisesRegex(ContractError, "malformed JSON"):
                    load_verified_json(path, require_sidecar=False)

    def test_duplicate_and_unknown_keys_are_not_echoed(self) -> None:
        secret_key = "secret\x1b[31mkey"
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "payload.json"
            path.write_text(
                '{"secret\\u001b[31mkey":1,"secret\\u001b[31mkey":2}\n',
                encoding="utf-8",
            )
            with self.assertRaises(ContractError) as duplicate:
                load_verified_json(path, require_sidecar=False)
            self.assertNotIn(secret_key, str(duplicate.exception))

        profile = load_verified_json(PROFILE)
        profile[secret_key] = True
        with self.assertRaises(ContractError) as unknown:
            validate_profile(profile)
        self.assertNotIn(secret_key, str(unknown.exception))

    def test_schema_bytes_are_bound_to_trusted_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            shutil.copytree(ROOT / "docs/benchmarks/v1", root / "docs/benchmarks/v1")
            shutil.copytree(ROOT / "docs/schemas", root / "docs/schemas")
            schema = root / "docs/schemas/benchmark-outcome-v1.schema.json"
            schema.write_text("[]\n", encoding="utf-8")
            digest = hashlib.sha256(schema.read_bytes()).hexdigest()
            schema.with_suffix(".json.sha256").write_text(
                f"{digest}  {schema.name}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(ContractError, "trusted schema digest mismatch"):
                verify_contract(root)

    def test_journeys_define_specific_machine_boundaries(self) -> None:
        expected_checks = {
            "pr_ready_bug_fix": "reproduction_before",
            "dependency_security_upgrade": "advisory_check_after",
            "bounded_refactor": "observable_behavior_equivalent",
        }
        journeys = ROOT / "docs/benchmarks/v1/journeys"
        for path in journeys.glob("*.json"):
            value = load_verified_json(path)
            with self.subTest(journey=value["journey_id"]):
                self.assertIn(expected_checks[value["journey_id"]], value["required_checks"])
                self.assertIn("all_required_checks_pass", value["success_conditions"])
                self.assertIn("required_check_failed", value["failure_conditions"])


if __name__ == "__main__":
    unittest.main()
