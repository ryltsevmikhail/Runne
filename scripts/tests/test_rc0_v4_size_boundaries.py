"""Exact u64 boundary coverage for evidence profile v4."""

from __future__ import annotations

import unittest
from copy import deepcopy

from scripts.rc0_policy.canonical import loads_canonical
from scripts.rc0_policy.schemas import validate_schema
from scripts.tests.rc0_platform_policy_support import (
    PROFILE_V4,
    valid_declaration_fixture,
)


MAX = 2**64 - 1


class Rc0V4SizeBoundaryTests(unittest.TestCase):
    def test_artifact_inventory_accepts_max_and_rejects_one_above(self) -> None:
        from scripts.tests.test_rc0_candidate_evidence import fixture_records_v4

        record = fixture_records_v4()["artifact-inventory.json"]
        maximum = deepcopy(record)
        maximum["artifacts"][0]["size"] = MAX
        self.assertEqual(
            validate_schema(maximum, "gocode.rc0.schema.artifact-inventory/4"), ()
        )
        maximum["artifacts"][0]["size"] = MAX + 1
        diagnostics = validate_schema(
            maximum, "gocode.rc0.schema.artifact-inventory/4"
        )
        self.assertTrue(any("above maximum" in item for item in diagnostics))

    def test_checksums_model_accepts_max_and_rejects_one_above(self) -> None:
        from scripts.rc0_policy.model import parse_checksums_text
        from scripts.tests.test_rc0_candidate_evidence import ATTEMPT, POLICY, SOURCE

        header = (
            "repository_id=gocode\n"
            f"candidate_source_revision={SOURCE}\n"
            f"evidence_attempt_id={ATTEMPT}\n"
            f"policy_digest={POLICY}\n"
        )
        for size, accepted in ((MAX, True), (MAX + 1, False)):
            with self.subTest(size=size):
                raw = (header + "c" * 64 + f" {size} dist/gocode.tar\n").encode()
                if accepted:
                    parsed = parse_checksums_text(raw)
                    parsed["schema_id"] = "gocode.rc0.schema.checksums-text/4"
                else:
                    with self.assertRaisesRegex(Exception, "artifact size exceeds u64"):
                        parse_checksums_text(raw)
                    continue
                diagnostics = validate_schema(
                    parsed, "gocode.rc0.schema.checksums-text/4"
                )
                self.assertEqual(not diagnostics, accepted)

    def test_verification_report_accepts_max_and_rejects_one_above(self) -> None:
        fixture = valid_declaration_fixture(profile=PROFILE_V4)
        payload = loads_canonical(fixture.report.payload_canonical_bytes)
        for size, accepted in ((MAX, True), (MAX + 1, False)):
            with self.subTest(size=size):
                changed = deepcopy(payload)
                changed["exact_artifact_bindings"][0]["size"] = size
                for row in changed["required_gate_results"]:
                    row["binding"]["exact_artifact_bindings"][0]["size"] = size
                diagnostics = validate_schema(
                    changed, "gocode.rc0.schema.verification-report/4"
                )
                self.assertEqual(not diagnostics, accepted)


if __name__ == "__main__":
    unittest.main()
