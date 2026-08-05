"""Independent negative Task 12 acceptance semantics for AT39–AT42."""

import unittest
from dataclasses import replace

from scripts.release_v2.claims import current_claim_matrix, fixture_gate_result, production_gate_exit_code, validate_claim_matrix
from scripts.release_v2.model import ClaimDisposition, FailureCodeV1, ReleaseFailure


class ClaimAcceptanceTests(unittest.TestCase):
    def test_at_39_fixture_verified_disposition_blocks(self) -> None:
        matrix = current_claim_matrix("a" * 64)
        invalid = (replace(matrix.claims[0], disposition=ClaimDisposition.VERIFIED),) + matrix.claims[1:]
        self._blocks(invalid, matrix.subject_sha256)

    def test_at_40_duplicate_claim_disposition_blocks(self) -> None:
        matrix = current_claim_matrix("a" * 64)
        self._blocks((matrix.claims[0],) + matrix.claims, matrix.subject_sha256)

    def test_at_41_unknown_or_escalated_claim_blocks(self) -> None:
        matrix = current_claim_matrix("a" * 64)
        invalid = (replace(matrix.claims[0], claim_id="unknown_claim"),) + matrix.claims[1:]
        self._blocks(invalid, matrix.subject_sha256)

    def test_at_42_production_gate_fails_closed_nonzero(self) -> None:
        result = fixture_gate_result(current_claim_matrix("a" * 64))
        self.assertEqual((result.production_gate.disposition.value, production_gate_exit_code(result)), ("BLOCKED", 1))

    def _blocks(self, claims: tuple[object, ...], subject: str) -> None:
        with self.assertRaises(ReleaseFailure) as raised:
            validate_claim_matrix(claims, subject)
        self.assertIs(raised.exception.code, FailureCodeV1.CLAIM_UNSUPPORTED)
