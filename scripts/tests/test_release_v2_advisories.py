import inspect
import json
import unittest

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.dependencies_types import DependencyPackageV1
from scripts.release_v2.model import FailureCodeV1
from scripts.tests.test_release_v2_legal import _blocks, _fixture, _inventory, _package, _package_value, _policy as _license_policy, _report, _subject


class AdvisoryTests(unittest.TestCase):
    def test_at_30_fixture_not_affected_is_structurally_accepted(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="NOT_AFFECTED")
        _validate_fixture(raw, *context)
        self.assertEqual(json.loads(raw)["source"]["environment_class"], "FIXTURE")

    def test_at_30_self_declared_imported_signed_production_blocks(self) -> None:
        context = _context()
        raw = _report_with(_fixture_report(*context), source={"authenticity_method": "IMPORTED_SIGNED", "environment_class": "PRODUCTION"})
        _blocks(self, lambda: _validate_production(raw, *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_30_advisory_blocked(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="BLOCKED")
        _blocks(self, lambda: _validate_fixture(raw, *context), FailureCodeV1.ADVISORY_BLOCKED)

    def test_at_31_fixture_policy_requires_exact_scanner_and_database(self) -> None:
        context = _context()
        raw = _fixture_report(*context)
        for changed in ({"scanner": {"name": "other"}}, {"scanner": {"tool_sha256": "0" * 64}}, {"database": {"authority": "other"}}, {"database": {"digest": "0" * 64}}):
            with self.subTest(changed=changed):
                _blocks(self, lambda changed=changed: _validate_fixture(_report_with(raw, **changed), *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_31_stale_or_future_database_blocks(self) -> None:
        context = _context()
        raw = _fixture_report(*context)
        for changed in ({"database": {"fresh_until": 10}}, {"database": {"snapshot_date": 11}}):
            with self.subTest(changed=changed):
                _blocks(self, lambda changed=changed: _validate_fixture(_report_with(raw, **changed), *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_32_remediated_requires_fixed_version(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="REMEDIATED")
        _blocks(self, lambda: _validate_fixture(raw, *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_32_accepted_risk_requires_exact_subject_inventory_and_review(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="ACCEPTED_RISK", owner="owner", reviewer="reviewer", expiry=11)
        _validate_fixture(raw, *context)
        finding = json.loads(raw)["findings"][0]
        for changed in ({"qualification_subject_sha256": "0" * 64}, {"inventory_sha256": "0" * 64}, {"affected_component": _package_value(_package("MIT", name="other"))}, {"reviewer": "owner"}, {"expiry": 10}):
            with self.subTest(changed=changed):
                _blocks(self, lambda changed=changed: _validate_fixture(_report_with(raw, findings=[finding | changed]), *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_32_unknown_and_report_missing_dispositions_block(self) -> None:
        context = _context()
        for disposition in ("UNKNOWN", "REPORT_MISSING"):
            with self.subTest(disposition=disposition):
                _blocks(self, lambda disposition=disposition: _validate_fixture(_fixture_report(*context, disposition=disposition), *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_32_findings_must_be_ordered_and_unique(self) -> None:
        context = _context()
        raw = _fixture_report(*context)
        finding = json.loads(raw)["findings"][0]
        unsorted = finding | {"advisory_id": "AAAA-0000"}
        for findings in ([finding, finding], [finding, unsorted]):
            with self.subTest(findings=findings):
                _blocks(self, lambda findings=findings: _validate_fixture(_report_with(raw, findings=findings), *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_32_control_character_collision_cannot_bypass_tuple_ordering(self) -> None:
        first = _package("MIT")
        second = DependencyPackageV1("\0cargo", "component", "1.0.0", "https://crates.io/index", "a" * 64, "MIT", (), True)
        context = _context(first, second)
        raw = _fixture_report(*context, advisory_id="GHSA-abcd\0")
        finding = json.loads(raw)["findings"][0]
        colliding = finding | {"advisory_id": "GHSA-abcd", "affected_component": _package_value(second)}
        _blocks(self, lambda: _validate_fixture(_report_with(raw, findings=[finding, colliding]), *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_32_safe_findings_are_accepted_in_tuple_order(self) -> None:
        context = _context(_package("MIT", name="alpha"), _package("MIT", name="beta"))
        raw = _fixture_report(*context, advisory_id="GHSA-abcd-1234-5678")
        finding = json.loads(raw)["findings"][0]
        ordered = finding | {"advisory_id": "GHSA-bcde-1234-5678", "affected_component": _package_value(context[0].packages[1])}
        _validate_fixture(_report_with(raw, findings=[finding, ordered]), *context)

    def test_at_33_fixture_structure_never_validates_production(self) -> None:
        context = _context()
        raw = _fixture_report(*context, disposition="REMEDIATED", fixed_version="1.0.1")
        _validate_fixture(raw, *context)
        _blocks(self, lambda: _validate_production(raw, *context), FailureCodeV1.ADVISORY_REPORT_MISSING)
        production = _report_with(raw, source={"environment_class": "PRODUCTION"})
        _blocks(self, lambda: _validate_fixture(production, *context), FailureCodeV1.ADVISORY_REPORT_MISSING)

    def test_at_33_fixture_report_is_independently_validated_against_policy(self) -> None:
        from scripts.release_v2.advisories import validate_advisory_report

        context = _context()
        raw = _fixture_report(*context)
        self.assertNotIn("task9_validated_evidence", inspect.signature(validate_advisory_report).parameters)
        _validate_fixture(raw, *context)
        _blocks(self, lambda: _validate_fixture(_report_with(raw, scanner={"name": "other"}), *context), FailureCodeV1.ADVISORY_REPORT_MISSING)
        _blocks(self, lambda: _validate_production(raw, *context), FailureCodeV1.ADVISORY_REPORT_MISSING)


def _context(*packages):
    from scripts.release_v2.licenses import LicenseDisposition, bind_license_report

    artifacts, product = _fixture()
    inventory = _inventory(*(packages or (_package("MIT"),)))
    bound = bind_license_report(product, _report(inventory, product, artifacts, _license_policy("MIT", LicenseDisposition.ALLOWED), ()))
    return inventory, bound, artifacts, _subject(bound)


def _fixture_report(inventory, product, artifacts, subject, *, disposition="NOT_AFFECTED", **finding):
    package = _package_value(inventory.packages[0])
    result = {"advisory_id": "GHSA-abcd-1234-5678", "affected_component": package, "approval_source": "IMPORTED_RECORD", "candidate_sha256": artifacts.candidate_sha256, "disposition": disposition, "expiry": None, "fixed_version": None, "inventory_sha256": inventory.inventory_sha256, "owner": "scanner", "qualification_subject_sha256": subject.subject_sha256, "rationale": "scanner_imported_record", "reachability": None, "reachability_evidence": None, "reviewer": None, "severity": "HIGH"} | finding
    return canonical_json({"candidate_sha256": artifacts.candidate_sha256, "database": {"authority": "OSV", "digest": "b" * 64, "fresh_until": 11, "snapshot_date": 9}, "findings": [result], "inventory_sha256": inventory.inventory_sha256, "qualification_subject_sha256": subject.subject_sha256, "scanner": {"name": "osv_scanner", "tool_sha256": "d" * 64, "version": "1.0.0"}, "schema_version": "advisory-report.v1", "source": {"authenticity_method": "STRUCTURAL_FIXTURE", "digest": "c" * 64, "environment_class": "FIXTURE", "fresh_until": 11, "produced_at": 9}})


def _report_with(raw, **changes):
    document = json.loads(raw)
    for key, value in changes.items():
        document[key] = document[key] | value if type(value) is dict else value
    return canonical_json(document)


def _policy():
    from scripts.release_v2.advisories import AdvisoryValidationPolicy

    return AdvisoryValidationPolicy("osv_scanner", "1.0.0", "d" * 64, "OSV", "b" * 64, 9, 11)


def _validate_fixture(raw, inventory, product, artifacts, subject):
    from scripts.release_v2.advisories import validate_advisory_report

    validate_advisory_report(raw, inventory, product, artifact_inventory=artifacts, qualification_subject=subject, trusted_evaluation_time=10, structural_fixture=True, validation_policy=_policy())


def _validate_production(raw, inventory, product, artifacts, subject):
    from scripts.release_v2.advisories import validate_advisory_report

    validate_advisory_report(raw, inventory, product, artifact_inventory=artifacts, qualification_subject=subject, trusted_evaluation_time=10, validation_policy=_policy())
