import hashlib
import json
import unittest
from dataclasses import replace

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.dependencies_types import DependencyPackageV1
from scripts.release_v2.model import ArtifactEntry, ArtifactInventoryV2, FailureCodeV1, ProductTupleIdentityV1, QualificationSubjectIdentityV1, ReleaseFailure
from scripts.tests.release_v2_support import dependency_inventory


class LicenseTests(unittest.TestCase):
    def test_at_23_known_license_policy_is_accepted(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package("MIT")), _policy("MIT", LicenseDisposition.ALLOWED)
        raw = _report(inventory, product, artifacts, policy, ())
        _validate(raw, inventory, product, artifacts, policy, ())
        self.assertEqual(json.loads(raw)["candidate_sha256"], artifacts.candidate_sha256)

    def test_at_23_unknown_license_blocks(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package(None)), _policy("MIT", LicenseDisposition.ALLOWED)
        raw = _report(inventory, product, artifacts, policy, ())
        self.assertEqual(json.loads(raw)["records"][0]["detected_spdx_expression"], "UNKNOWN")
        _blocks(self, lambda: _validate(raw, inventory, product, artifacts, policy, ()), FailureCodeV1.LICENSE_EVIDENCE_MISSING)

    def test_at_26_allowed_license_is_accepted(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        raw = _report(_inventory(_package("MIT")), product, artifacts, _policy("MIT", LicenseDisposition.ALLOWED), ())
        self.assertEqual(json.loads(raw)["records"][0]["disposition"], "ALLOWED")

    def test_at_26_denied_license_blocks(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package("GPL-3.0-only")), _policy("GPL-3.0-only", LicenseDisposition.DENIED)
        raw = _report(inventory, product, artifacts, policy, ())
        _blocks(self, lambda: _validate(raw, inventory, product, artifacts, policy, ()), FailureCodeV1.LICENSE_DENIED)

    def test_at_27_denied_license_is_reported(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        raw = _report(_inventory(_package("GPL-3.0-only")), product, artifacts, _policy("GPL-3.0-only", LicenseDisposition.DENIED), ())
        self.assertEqual(json.loads(raw)["records"][0]["disposition"], "DENIED")

    def test_at_27_denied_license_cannot_be_overridden(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package("GPL-3.0-only")), _policy("GPL-3.0-only", LicenseDisposition.DENIED)
        exception = _exception("GPL-3.0-only", "DENIED", product, artifacts)
        _blocks(self, lambda: _report(inventory, product, artifacts, policy, (exception,)), FailureCodeV1.LICENSE_EVIDENCE_MISSING)

    def test_at_28_complete_license_evidence_is_accepted(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory = _inventory(_package("MIT"), _package("Apache-2.0", name="second"))
        policy = _policy("MIT", LicenseDisposition.ALLOWED, "Apache-2.0", LicenseDisposition.REVIEW_REQUIRED)
        exception = _exception("Apache-2.0", "REVIEW_REQUIRED", product, artifacts, name="second")
        raw = _report(inventory, product, artifacts, policy, (exception,))
        self.assertEqual([row["package"]["name"] for row in json.loads(raw)["records"]], ["component", "second"])

    def test_at_28_unknown_or_missing_license_evidence_blocks(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package("MIT"), _package("Apache-2.0", name="second")), _policy("MIT", LicenseDisposition.ALLOWED)
        raw = _report(inventory, product, artifacts, policy, ())
        _blocks(self, lambda: _validate(raw, inventory, product, artifacts, policy, ()), FailureCodeV1.LICENSE_EVIDENCE_MISSING)

    def test_at_29_independently_reviewed_unexpired_exception_is_accepted(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package("Apache-2.0")), _policy("Apache-2.0", LicenseDisposition.REVIEW_REQUIRED)
        exception = _exception("Apache-2.0", "REVIEW_REQUIRED", product, artifacts)
        raw = _report(inventory, product, artifacts, policy, (exception,))
        _validate(raw, inventory, product, artifacts, policy, (exception,))
        record = json.loads(raw)["records"][0]
        self.assertEqual(record["disposition"], "EXCEPTION_APPROVED")
        self.assertEqual({key: record[key] for key in ("evidence_source", "exception_owner", "reviewer", "rationale", "expiry", "package")}, {"evidence_source": "IMPORTED_RECORD", "exception_owner": "owner", "reviewer": "reviewer", "rationale": "approved_exception", "expiry": 11, "package": _package_value(_package("Apache-2.0"))})

    def test_at_29_policy_cannot_directly_approve_exception(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory = _inventory(_package("Apache-2.0"))
        policy = _policy("Apache-2.0", LicenseDisposition.EXCEPTION_APPROVED)
        _blocks(self, lambda: _report(inventory, product, artifacts, policy, ()), FailureCodeV1.LICENSE_EVIDENCE_MISSING)

    def test_at_29_exception_without_owner_or_expiry_blocks(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package("Apache-2.0")), _policy("Apache-2.0", LicenseDisposition.REVIEW_REQUIRED)
        for changed in ({"owner": ""}, {"expiry": 10}, {"reviewer": "owner"}):
            with self.subTest(changed=changed):
                exception = _exception("Apache-2.0", "REVIEW_REQUIRED", product, artifacts) | changed
                _blocks(self, lambda: _report(inventory, product, artifacts, policy, (exception,)), FailureCodeV1.LICENSE_EVIDENCE_MISSING)

    def test_report_is_canonical_and_contains_complete_inventory_identity(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package("MIT")), _policy("MIT", LicenseDisposition.ALLOWED, notices=frozenset({"MIT"}))
        notices = _notices(_package("MIT"), artifacts)
        first = _report(inventory, product, artifacts, policy, (), notices)
        second = _report(inventory, product, artifacts, policy, (), notices)
        record = json.loads(first)["records"][0]
        self.assertEqual(first, second)
        self.assertEqual(first, canonical_json(json.loads(first)))
        self.assertEqual(record["package"], _package_value(_package("MIT")))
        self.assertEqual(record["notice_artifact"], {"path": "NOTICE", "sha256": artifacts.entries[0].sha256})

    def test_exception_requires_exact_full_subject_and_closed_prevalidation(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition, bind_license_report

        artifacts, product = _fixture()
        inventory, policy = _inventory(_package("Apache-2.0")), _policy("Apache-2.0", LicenseDisposition.REVIEW_REQUIRED)
        exception = _exception("Apache-2.0", "REVIEW_REQUIRED", product, artifacts)
        raw = _report(inventory, product, artifacts, policy, (exception,))
        bound = bind_license_report(product, raw)
        subject = _subject(bound)
        approved = exception | {"qualification_subject_sha256": subject.subject_sha256}
        for changed in ({"qualification_subject_sha256": "0" * 64}, {"package": _package_value(_package("Apache-2.0", name="other"))}, {"unexpected": "field"}):
            with self.subTest(changed=changed):
                altered = approved | changed
                _blocks(self, lambda: _validate_exact(raw, inventory, product, artifacts, policy, (altered,), subject), FailureCodeV1.LICENSE_EVIDENCE_MISSING)
        for field, value in (("build_input_sha256", "f" * 64), ("artifact_inventory_sha256", "f" * 64), ("sbom_sha256", "f" * 64), ("license_report_sha256", "f" * 64), ("provenance_sha256", "f" * 64), ("components", ("Other",)), ("schema_revision", "other-v1")):
            with self.subTest(field=field):
                _blocks(self, lambda field=field, value=value: _validate_exact(raw, inventory, replace(bound, **{field: value}), artifacts, policy, (approved,), subject), FailureCodeV1.LICENSE_EVIDENCE_MISSING)

    def test_notice_evidence_requires_exact_verified_data_artifact(self) -> None:
        from scripts.release_v2.licenses import LicenseDisposition

        artifacts, product = _fixture()
        package, inventory = _package("MIT"), _inventory(_package("MIT"))
        policy = _policy("MIT", LicenseDisposition.ALLOWED, notices=frozenset({"MIT"}))
        notices = _notices(package, artifacts)
        raw = _report(inventory, product, artifacts, policy, (), notices)
        _validate(raw, inventory, product, artifacts, policy, (), notices)
        for altered in ((), ({"package": _package_value(_package("MIT", name="other")), "notice": notices[0]["notice"]},), ({"package": _package_value(package), "notice": {"path": "NOTICE", "sha256": "0" * 64}},)):
            with self.subTest(altered=altered):
                _blocks(self, lambda altered=altered: _report(inventory, product, artifacts, policy, (), altered), FailureCodeV1.LICENSE_EVIDENCE_MISSING)


def _package(license_name: str | None, *, name: str = "component") -> DependencyPackageV1:
    return DependencyPackageV1("cargo", name, "1.0.0", "https://crates.io/index", "a" * 64, license_name, (), True)


def _package_value(package: DependencyPackageV1) -> dict[str, str]:
    return {"ecosystem": package.ecosystem, "lock_locator": package.lock_locator, "name": package.name, "source_digest": package.source_digest, "version": package.version}


def _inventory(*packages: DependencyPackageV1):
    return dependency_inventory(*packages)


def _fixture() -> tuple[ArtifactInventoryV2, ProductTupleIdentityV1]:
    entry = ArtifactEntry("NOTICE", "file", "0644", 7, hashlib.sha256(b"notice\n").hexdigest())
    candidate = hashlib.sha256(canonical_json([{"kind": entry.kind, "mode": entry.mode, "path": entry.path, "sha256": entry.sha256, "size": entry.size}])).hexdigest()
    digest = hashlib.sha256(canonical_json({"candidate_sha256": candidate, "entries": [{"kind": entry.kind, "mode": entry.mode, "path": entry.path, "sha256": entry.sha256, "size": entry.size}], "schema_version": "artifact-inventory-v2"})).hexdigest()
    artifacts = ArtifactInventoryV2("artifact-inventory-v2", candidate, (entry,), digest)
    return artifacts, ProductTupleIdentityV1("a" * 64, digest, "c" * 64, "0" * 64, "d" * 64, ("Desktop",), "product-tuple-v1")


def _report(inventory, product, artifacts, policy, exceptions, notices=()):
    from scripts.release_v2.licenses import build_license_report

    return build_license_report(inventory, product, policy, exceptions, artifact_inventory=artifacts, notice_artifacts=notices, source_date_epoch=10)


def _subject(product: ProductTupleIdentityV1) -> QualificationSubjectIdentityV1:
    payload = {"artifact_inventory_sha256": product.artifact_inventory_sha256, "build_input_sha256": product.build_input_sha256, "components": list(product.components), "license_report_sha256": product.license_report_sha256, "provenance_sha256": product.provenance_sha256, "sbom_sha256": product.sbom_sha256, "schema_revision": product.schema_revision}
    tuple_sha256 = hashlib.sha256(canonical_json(payload)).hexdigest()
    return QualificationSubjectIdentityV1(product.build_input_sha256, tuple_sha256, hashlib.sha256(canonical_json({"build_input_sha256": product.build_input_sha256, "product_tuple_sha256": tuple_sha256})).hexdigest())


def _exception(license_name, disposition, product, artifacts, *, name="component", owner="owner", reviewer="reviewer", expiry=11):
    package = _package(license_name, name=name)
    return {"candidate_sha256": artifacts.candidate_sha256, "disposition": disposition, "evidence_source": "IMPORTED_RECORD", "expiry": expiry, "license": license_name, "owner": owner, "package": _package_value(package), "qualification_subject_sha256": "0" * 64, "rationale": "approved_exception", "reviewer": reviewer}


def _notices(package, artifacts):
    return ({"package": _package_value(package), "notice": {"path": artifacts.entries[0].path, "sha256": artifacts.entries[0].sha256}},)


def _validate(raw, inventory, product, artifacts, policy, exceptions, notices=()):
    from scripts.release_v2.licenses import bind_license_report

    bound = bind_license_report(product, raw)
    subject = _subject(bound)
    amended = tuple(exception | {"qualification_subject_sha256": subject.subject_sha256} for exception in exceptions)
    _validate_exact(raw, inventory, bound, artifacts, policy, amended, subject, notices)


def _validate_exact(raw, inventory, product, artifacts, policy, exceptions, subject, notices=()):
    from scripts.release_v2.licenses import validate_license_report

    validate_license_report(raw, inventory, product, policy, exceptions, artifact_inventory=artifacts, qualification_subject=subject, notice_artifacts=notices, source_date_epoch=10)


def _policy(*values, notices=frozenset()):
    from scripts.release_v2.licenses import LicenseEvidenceSource, LicensePolicyRecordV1

    return tuple(sorted((LicensePolicyRecordV1(values[index], values[index + 1], LicenseEvidenceSource.COMMITTED_RECORD, values[index] in notices, "policy_reviewer", "approved_policy", None) for index in range(0, len(values), 2)), key=lambda item: item.spdx_expression.encode("utf-8")))


def _blocks(case: unittest.TestCase, callback: object, code: FailureCodeV1) -> None:
    with case.assertRaises(ReleaseFailure) as raised:
        callback()
    case.assertIs(raised.exception.code, code)
