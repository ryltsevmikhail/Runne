"""Ingestion core tests for macOS production signing evidence (SYNTHETIC data)."""

import json
import unittest

from scripts.macos_signing.ingestion import IngestionStatus, ingest_production_evidence
from scripts.macos_signing.ingestion_rules import evidence_digest, strict_json_loads
from scripts.macos_signing.models import FailureCode
from scripts.tests import macos_signing_activation_support as support
from scripts.tests import macos_signing_support

_TOP_LEVEL_KEYS = (
    "schema_version",
    "kind",
    "profile",
    "platform",
    "environment_class",
    "authenticity_method",
    "producer_lane",
    "candidate",
    "signature",
    "target",
    "entitlements",
    "commands",
    "notarization",
    "stapling",
    "gatekeeper",
    "produced_at",
    "fresh_until",
    "review",
    "evidence_sha256",
)


class MacOSSigningProductionActivationTests(unittest.TestCase):
    def _identity(self):
        return support.synthetic_identity()

    def _expectation(self):
        return support.synthetic_expectation()

    def test_verified_ingestion_is_deterministic(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.synthetic_document(identity, expectation)
        first = ingest_production_evidence(document, identity, expectation, support.NOW)
        second = ingest_production_evidence(support.finalized(document), identity, expectation, support.NOW)
        self.assertEqual(first.status, IngestionStatus.VERIFIED)
        self.assertIsNone(first.failure)
        self.assertEqual(first.evidence_sha256, document["evidence_sha256"])
        self.assertEqual(first.evidence_sha256, evidence_digest(document))
        self.assertEqual(first, second)

    def test_missing_required_field_is_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        for key in _TOP_LEVEL_KEYS:
            with self.subTest(key=key):
                document = support.without(support.synthetic_document(identity, expectation), key)
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.EVIDENCE_INCOMPLETE)

    def test_extra_fields_are_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        base = support.synthetic_document(identity, expectation)
        cases = (
            ({**base, "extra": "value"}, "top-level"),
            (support.with_changed(base, ("candidate",), {**base["candidate"], "extra": "value"}), "candidate"),
            (support.with_changed(base, ("review",), {**base["review"], "extra": "value"}), "review"),
            (support.with_changed(base, ("commands", 0), {**base["commands"][0], "extra": "value"}), "command-record"),
        )
        for document, location in cases:
            with self.subTest(location=location):
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.EVIDENCE_INCOMPLETE)

    def test_stale_evidence_is_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        base = support.synthetic_document(identity, expectation)
        cases = (
            ("now past fresh_until", support.with_changed(base, ("fresh_until",), support.NOW - 1)),
            ("window exceeds limit", support.with_changed(base, ("produced_at",), support.NOW - 700_000)),
            ("produced after now", support.with_changed(base, ("produced_at",), support.NOW + 1)),
        )
        for label, document in cases:
            with self.subTest(label=label):
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.EVIDENCE_STALE)

    def test_candidate_mismatch_is_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        base = support.synthetic_document(identity, expectation)
        cases = (
            ("tree_sha256", support.with_changed(base, ("candidate", "tree_sha256"), "0" * 64)),
            ("relative_name", support.with_changed(base, ("candidate", "relative_name"), "Other.app")),
            ("entitlement digest", support.with_changed(base, ("entitlements", "app_sha256"), "0" * 64)),
        )
        for label, document in cases:
            with self.subTest(label=label):
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)

    def test_signature_mismatch_is_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        base = support.synthetic_document(identity, expectation)
        cases = (
            ("cdhash", support.with_changed(base, ("signature", "cdhash"), "d" * 40)),
            ("team_identifier", support.with_changed(base, ("signature", "team_identifier"), "TEAM000002")),
        )
        for label, document in cases:
            with self.subTest(label=label):
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)

    def test_review_owner_reviewer_case_insensitive_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        base = support.synthetic_document(identity, expectation)
        document = support.with_changed(
            support.with_changed(base, ("review", "owner"), "Operator-A"),
            ("review", "reviewer"),
            "operator-a",
        )
        result = ingest_production_evidence(document, identity, expectation, support.NOW)
        self.assertEqual(result.status, IngestionStatus.REJECTED)
        self.assertEqual(result.failure.code, FailureCode.EVIDENCE_INCOMPLETE)
        self.assertEqual(result.failure.phase, "review")

    def test_profile_downgrade_is_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.with_changed(support.synthetic_document(identity, expectation), ("profile",), "development-ad-hoc")
        result = ingest_production_evidence(document, identity, expectation, support.NOW)
        self.assertEqual(result.status, IngestionStatus.REJECTED)
        self.assertEqual(result.failure.code, FailureCode.PROFILE_DOWNGRADE_REJECTED)

    def test_synthetic_evidence_is_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        base = support.synthetic_document(identity, expectation)
        for environment_class in ("FIXTURE", "SYNTHETIC"):
            with self.subTest(environment_class=environment_class):
                document = support.with_changed(base, ("environment_class",), environment_class)
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.SYNTHETIC_EVIDENCE_REJECTED)
        for path, value in (("schema_version", "evidence-v1"), ("kind", "development-signing")):
            with self.subTest(field=path):
                document = support.with_changed(base, (path,), value)
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.SYNTHETIC_EVIDENCE_REJECTED)
        development = macos_signing_support.development_evidence()
        payload = json.loads(macos_signing_support.normalize_evidence(development).decode("utf-8"))
        result = ingest_production_evidence(payload, identity, expectation, support.NOW)
        self.assertEqual(result.status, IngestionStatus.REJECTED)

    def test_secret_markers_are_rejected_and_redacted(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        cases = (
            (("review", "review_id"), "-----BEGIN PRIVATE KEY-----"),
            (("review", "reviewer_role"), "keep-this-password-secret"),
            (("signature", "bundle_id"), "/Users/operator/key.p12"),
            (("review", "review_id"), "$HOME-secret"),
            (("review", "review_id"), "Bearer abc"),
        )
        for path, marker in cases:
            with self.subTest(path=path):
                document = support.with_changed(support.synthetic_document(identity, expectation), path, marker)
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.EVIDENCE_SECRET_MARKER)
                self.assertEqual(result.failure.phase, "secret-scan")
                self.assertEqual(result.failure.candidate_id, "")
                self.assertNotIn(marker, str(result.failure))

    def test_disposition_failures(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        base = support.synthetic_document(identity, expectation)
        cases = (
            ("notarization", FailureCode.NOTARIZATION_FAILED),
            ("stapling", FailureCode.STAPLE_FAILED),
            ("gatekeeper", FailureCode.GATEKEEPER_ASSESSMENT_FAILED),
        )
        for field, code in cases:
            with self.subTest(field=field):
                document = support.with_changed(base, (field,), "not-accepted")
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, code)

    def test_command_mismatches(self) -> None:
        identity, expectation = self._identity(), self._expectation()

        def build(kind: str):
            document = support.synthetic_document(identity, expectation)
            if kind == "missing phase":
                return support.with_changed(document, ("commands",), document["commands"][:13])
            if kind == "duplicate phase":
                commands = [dict(record) for record in document["commands"]]
                commands[5] = dict(commands[4])
                return support.with_changed(document, ("commands",), commands)
            if kind == "permuted phases":
                commands = [dict(record) for record in document["commands"]]
                commands[0], commands[1] = commands[1], commands[0]
                return support.with_changed(document, ("commands",), commands)
            if kind == "different target":
                return support.with_changed(document, ("commands", 11, "target"), "Other.app")
            if kind == "runtime disabled":
                return support.with_changed(document, ("commands", 0, "hardened_runtime"), False)
            return support.with_changed(document, ("commands", 0, "outcome"), "failure")

        cases = (
            ("missing phase", FailureCode.EVIDENCE_INCOMPLETE),
            ("duplicate phase", FailureCode.EVIDENCE_INCOMPLETE),
            ("permuted phases", FailureCode.EVIDENCE_INCOMPLETE),
            ("different target", FailureCode.ARTIFACT_IDENTITY_MISMATCH),
            ("runtime disabled", FailureCode.SIGNATURE_INVALID),
            ("outcome failure", FailureCode.SIGNATURE_INVALID),
        )
        for label, code in cases:
            with self.subTest(label=label):
                result = ingest_production_evidence(build(label), identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, code)

    def test_digest_mismatch_is_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.with_changed(support.synthetic_document(identity, expectation), ("evidence_sha256",), "0" * 64)
        result = ingest_production_evidence(document, identity, expectation, support.NOW)
        self.assertEqual(result.status, IngestionStatus.REJECTED)
        self.assertEqual(result.failure.code, FailureCode.EVIDENCE_INTEGRITY)

    def test_strict_json_loads_rejects_non_finite_and_duplicates(self) -> None:
        for text in ('{"produced_at": NaN}', '{"a": 1, "a": 2}', '{"broken": '):
            with self.subTest(text=text):
                payload, ok = strict_json_loads(text)
                self.assertIsNone(payload)
                self.assertFalse(ok)

    def test_non_dict_payload_is_rejected(self) -> None:
        result = ingest_production_evidence(["not", "a", "document"], self._identity(), self._expectation(), support.NOW)
        self.assertEqual(result.status, IngestionStatus.REJECTED)
        self.assertEqual(result.failure.code, FailureCode.EVIDENCE_INCOMPLETE)

    def test_non_integer_timestamps_are_rejected(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        base = support.synthetic_document(identity, expectation)
        for value in (float(support.PRODUCED_AT), True):
            with self.subTest(value=value):
                document = support.with_changed(base, ("produced_at",), value)
                result = ingest_production_evidence(document, identity, expectation, support.NOW)
                self.assertEqual(result.status, IngestionStatus.REJECTED)
                self.assertEqual(result.failure.code, FailureCode.EVIDENCE_INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
