"""Independent negative Task 12 acceptance semantics for AT33–AT38."""

import unittest
from dataclasses import replace

from scripts.release_v2.model import FailureCodeV1
from scripts.tests.test_release_v2_evidence import _binding, _blocks, _records, _validate


class EvidenceAcceptanceTests(unittest.TestCase):
    def test_at_33_fixture_scan_is_not_production(self) -> None:
        records, binding = _records(), _binding()
        _blocks(self, lambda: _validate(records, binding, fixture=False), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_34_missing_hosted_lane_blocks(self) -> None:
        records, binding = _records(), _binding()
        _blocks(self, lambda: _validate(records[:-1], binding, fixture=True), FailureCodeV1.HOSTED_LANE_MISSING)

    def test_at_35_planned_lane_is_not_actual(self) -> None:
        records, binding = _records(), _binding()
        invalid = (replace(records[0], generation="PLANNED"),) + records[1:]
        _blocks(self, lambda: _validate(invalid, binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_36_wrong_candidate_evidence_blocks(self) -> None:
        records, binding = _records(), _binding()
        invalid = (replace(records[0], qualification_subject_sha256="0" * 64),) + records[1:]
        _blocks(self, lambda: _validate(invalid, binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_37_duplicate_or_stale_evidence_blocks(self) -> None:
        records, binding = _records(), _binding()
        _blocks(self, lambda: _validate(records + (records[0],), binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_38_self_review_rejected(self) -> None:
        records, binding = _records(), _binding()
        review = replace(records[0].review, reviewer=records[0].review.owner)
        invalid = (replace(records[0], review=review),) + records[1:]
        _blocks(self, lambda: _validate(invalid, binding, fixture=True), FailureCodeV1.SELF_APPROVAL_REJECTED)
