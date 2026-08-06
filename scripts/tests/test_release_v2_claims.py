import unittest

from scripts.release_v2.model import (
    ClaimDisposition,
    ClaimRecordV1,
    FailureCodeV1,
    GateResultV1,
    OverallStatus,
    ProductionGateV1,
)


class ClaimGateResultTests(unittest.TestCase):
    def test_gate_result_rejects_verified_claim_direct_construction(self) -> None:
        gate = ProductionGateV1(ClaimDisposition.BLOCKED, FailureCodeV1.PRODUCTION_GATE_BLOCKED)
        verified = ClaimRecordV1("claim", ClaimDisposition.VERIFIED, None, "a" * 64)

        with self.assertRaises(ValueError):
            GateResultV1("release-v2-result.v1", OverallStatus.BLOCKED_EVIDENCE, False, gate, (), (verified,))

    def test_production_gate_result_is_permanently_blocked(self) -> None:
        from scripts.release_v2.claims import current_claim_matrix, fixture_gate_result, production_gate_exit_code, production_gate_result

        matrix = current_claim_matrix("a" * 64)
        fixture = fixture_gate_result(matrix)
        self.assertEqual(fixture.failures, ())
        self.assertEqual(fixture.claims, matrix.claims)
        self.assertIsNotNone(fixture.fixture_status)
        result = production_gate_result(matrix)
        self.assertEqual(
            (result.overall_status.value, result.production_approved, result.production_gate.disposition.value, result.production_gate.failure_code.value),
            ("BLOCKED_EVIDENCE", False, "BLOCKED", "ProductionGateBlocked"),
        )
        self.assertIsNone(result.fixture_status)
        self.assertNotIn("fixture_status", result.as_dict())
        self.assertEqual(len(result.claims), 22)
        self.assertNotIn(ClaimDisposition.VERIFIED, (claim.disposition for claim in result.claims))
        self.assertEqual(production_gate_exit_code(result), 1)

    def test_structural_fixture_status_requires_no_failures(self) -> None:
        from scripts.release_v2.model import FailureRecordV1, FixtureStatus

        gate = ProductionGateV1(ClaimDisposition.BLOCKED, FailureCodeV1.PRODUCTION_GATE_BLOCKED)
        with self.assertRaises(ValueError):
            GateResultV1("release-v2-result.v1", OverallStatus.BLOCKED_EVIDENCE, False, gate, (FailureRecordV1(FailureCodeV1.EVIDENCE_MISSING, "evidence_missing"),), (), FixtureStatus.STRUCTURAL_FIXTURE_VALID)
