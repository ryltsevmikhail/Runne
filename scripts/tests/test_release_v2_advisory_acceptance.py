"""Independent Task 12 acceptance semantics for AT30–AT32."""

import json
import unittest

from scripts.release_v2.model import FailureCodeV1
from scripts.tests.test_release_v2_advisories import (
    _context, _fixture_report, _report_with, _validate_fixture,
)
from scripts.tests.test_release_v2_legal import _blocks, _package, _package_value


class AdvisoryAcceptanceTests(unittest.TestCase):
    def test_at_30_not_affected_advisory_is_accepted(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="NOT_AFFECTED")
        _validate_fixture(raw, *context)
        self.assertEqual(json.loads(raw)["findings"][0]["disposition"], "NOT_AFFECTED")

    def test_at_30_advisory_blocked(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="BLOCKED")
        _blocks(self, lambda: _validate_fixture(raw, *context), FailureCodeV1.ADVISORY_BLOCKED)

    def test_at_31_fresh_authenticated_advisory_is_accepted(self) -> None:
        context = _context()
        raw = _fixture_report(*context)
        _validate_fixture(raw, *context)
        report = json.loads(raw)
        self.assertEqual((report["source"]["authenticity_method"], report["database"]["fresh_until"]), ("STRUCTURAL_FIXTURE", 11))

    def test_at_31_missing_or_stale_advisory_blocks(self) -> None:
        context = _context()
        raw = _fixture_report(*context)
        stale = _report_with(raw, database={"fresh_until": 10})
        _blocks(self, lambda: _validate_fixture(stale, *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_32_exactly_bound_accepted_risk_is_accepted(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="ACCEPTED_RISK", owner="owner", reviewer="reviewer", expiry=11)
        _validate_fixture(raw, *context)
        self.assertEqual(json.loads(raw)["findings"][0]["qualification_subject_sha256"], context[3].subject_sha256)

    def test_at_32_accepted_risk_wrong_binding_blocks(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="ACCEPTED_RISK", owner="owner", reviewer="reviewer", expiry=11)
        finding = json.loads(raw)["findings"][0]
        invalid = _report_with(raw, findings=[finding | {"affected_component": _package_value(_package("MIT", name="other"))}])
        _blocks(self, lambda: _validate_fixture(invalid, *context), FailureCodeV1.ADVISORY_REPORT_MISSING)
