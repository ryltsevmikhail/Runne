"""Claim activation, schema drift, purity and finalize CLI tests (SYNTHETIC data)."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.macos_signing.claim_activation import (
    SIGNING_CLAIMS,
    ActivationReason,
    ClaimTransition,
    activate_claim_from_evidence,
    normalize_claim_activation,
)
from scripts.macos_signing.ingestion_rules import evidence_digest
from scripts.tests import macos_signing_activation_support as support

_ROOT = Path(__file__).resolve().parents[2]


def run_finalize(argv):
    from scripts.macos_signing import finalize

    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = finalize.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class MacOSSigningClaimActivationTests(unittest.TestCase):
    def _identity(self):
        return support.synthetic_identity()

    def _expectation(self):
        return support.synthetic_expectation()

    def test_fused_activation_success(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.synthetic_document(identity, expectation)
        for claim in SIGNING_CLAIMS:
            with self.subTest(claim=claim):
                activation = activate_claim_from_evidence(claim, document, identity, expectation, support.NOW, identity.release_candidate_sha256)
                self.assertEqual(activation.transition, ClaimTransition.ACTIVATED)
                self.assertEqual(activation.reason, ActivationReason.INGESTION_VERIFIED)
                self.assertEqual(activation.claim_id, claim)
                self.assertEqual(activation.candidate_digest, identity.release_candidate_sha256)
                self.assertEqual(activation.subject_sha256, identity.release_candidate_sha256)
                self.assertEqual(activation.evidence_sha256, document["evidence_sha256"])
                self.assertEqual(activation.evidence_sha256, evidence_digest(document))
                encoded = normalize_claim_activation(activation)
                self.assertEqual(list(json.loads(encoded)), ["candidate_digest", "claim_id", "evidence_sha256", "reason", "subject_sha256", "transition"])
                self.assertEqual(normalize_claim_activation(activation), encoded)

    def test_ingestion_exception_remains_blocked(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.synthetic_document(identity, expectation)
        with unittest.mock.patch(
            "scripts.macos_signing.claim_activation.ingest_production_evidence",
            side_effect=RuntimeError("boom"),
        ):
            activation = activate_claim_from_evidence(
                "macos_developer_id_signing", document, identity, expectation, support.NOW, identity.release_candidate_sha256
            )
        self.assertEqual(activation.transition, ClaimTransition.REMAINS_BLOCKED)
        self.assertEqual(activation.reason, ActivationReason.INGESTION_NOT_VERIFIED)
        self.assertIsNone(activation.evidence_sha256)

    def test_tampered_payload_remains_blocked(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.synthetic_document(identity, expectation)
        document["notarization"] = "not-accepted"
        activation = activate_claim_from_evidence("macos_developer_id_signing", document, identity, expectation, support.NOW, identity.release_candidate_sha256)
        self.assertEqual(activation.transition, ClaimTransition.REMAINS_BLOCKED)
        self.assertEqual(activation.reason, ActivationReason.INGESTION_NOT_VERIFIED)
        self.assertIsNone(activation.evidence_sha256)

    def test_subject_digest_mismatch(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.synthetic_document(identity, expectation)
        activation = activate_claim_from_evidence("macos_developer_id_signing", document, identity, expectation, support.NOW, "f" * 64)
        self.assertEqual(activation.transition, ClaimTransition.REMAINS_BLOCKED)
        self.assertEqual(activation.reason, ActivationReason.CANDIDATE_DIGEST_MISMATCH)
        self.assertEqual(activation.candidate_digest, identity.release_candidate_sha256)

    def test_unknown_claim_remains_blocked(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        activation = activate_claim_from_evidence("mcp_external_activation", support.synthetic_document(identity, expectation), identity, expectation, support.NOW, "f" * 64)
        self.assertEqual(activation.transition, ClaimTransition.REMAINS_BLOCKED)
        self.assertEqual(activation.reason, ActivationReason.UNKNOWN_CLAIM)
        self.assertEqual(activation.candidate_digest, identity.release_candidate_sha256)
        self.assertEqual(activation.subject_sha256, "f" * 64)
        self.assertIsNone(activation.evidence_sha256)

    def test_non_digest_subject_remains_blocked(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        activation = activate_claim_from_evidence("macos_developer_id_signing", support.synthetic_document(identity, expectation), identity, expectation, support.NOW, "not-a-digest")
        self.assertEqual(activation.transition, ClaimTransition.REMAINS_BLOCKED)
        self.assertEqual(activation.reason, ActivationReason.CANDIDATE_DIGEST_MISMATCH)

    def test_schema_matches_ingestion_rules(self) -> None:
        from scripts.macos_signing import ingestion_rules

        schema_path = _ROOT / "docs" / "schemas" / "macos-production-evidence-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        properties = schema["properties"]
        self.assertEqual(properties["schema_version"]["const"], ingestion_rules.SCHEMA_VERSION)
        self.assertEqual(properties["kind"]["const"], ingestion_rules.KIND)
        self.assertEqual(properties["profile"]["const"], ingestion_rules.PROFILE)
        self.assertEqual(properties["platform"]["const"], ingestion_rules.PLATFORM)
        self.assertEqual(properties["environment_class"]["const"], ingestion_rules.ENVIRONMENT_CLASS)
        self.assertEqual(properties["authenticity_method"]["const"], ingestion_rules.AUTHENTICITY_METHOD)
        self.assertEqual(properties["producer_lane"]["const"], ingestion_rules.PRODUCER_LANE)
        phases = [item["properties"]["phase"]["const"] for item in properties["commands"]["prefixItems"]]
        self.assertEqual(tuple(phases), ingestion_rules.CANONICAL_PHASES)

    def test_signing_claims_remain_blocked_upstream(self) -> None:
        from scripts.release_v2.claims import _CURRENT
        from scripts.release_v2.model import ClaimDisposition, FailureCodeV1

        current = dict((item[0], item) for item in _CURRENT)
        for claim in SIGNING_CLAIMS:
            with self.subTest(claim=claim):
                self.assertIn(claim, current)
                _, disposition, failure = current[claim]
                self.assertEqual(disposition, ClaimDisposition.BLOCKED_CREDENTIALS)
                self.assertEqual(failure, FailureCodeV1.SIGNING_BLOCKED_CREDENTIALS)

    def test_ingestion_sources_are_pure(self) -> None:
        for name in ("ingestion.py", "ingestion_rules.py", "claim_activation.py", "finalize.py"):
            source = (_ROOT / "scripts" / "macos_signing" / name).read_text(encoding="utf-8")
            for banned in ("os.environ", "subprocess", "socket", "urllib", "requests"):
                with self.subTest(file=name, banned=banned):
                    self.assertNotIn(banned, source)

    def test_finalize_adds_digest_and_is_idempotent(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.without(support.synthetic_document(identity, expectation), "evidence_sha256")
        path = Path(tempfile.mkdtemp()) / "evidence.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        code, stdout, stderr = run_finalize(["--evidence", str(path)])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        emitted = json.loads(stdout)
        self.assertEqual(emitted["evidence_sha256"], evidence_digest(document))
        code, stdout_again, stderr = run_finalize(["--evidence", str(path)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout_again), emitted)

    def test_finalize_rejects_secret_marker(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.synthetic_document(identity, expectation)
        marker = "-----BEGIN PRIVATE KEY-----"
        document["review"]["review_id"] = marker
        path = Path(tempfile.mkdtemp()) / "evidence.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        code, stdout, stderr = run_finalize(["--evidence", str(path)])
        self.assertEqual(code, 1)
        self.assertIn("EVIDENCE_SECRET_MARKER", stderr)
        self.assertNotIn(marker, stdout + stderr)

    def test_finalize_rejects_bad_existing_digest(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        document = support.synthetic_document(identity, expectation)
        document["evidence_sha256"] = "0" * 64
        path = Path(tempfile.mkdtemp()) / "evidence.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        code, stdout, stderr = run_finalize(["--evidence", str(path)])
        self.assertEqual(code, 1)
        self.assertIn("EVIDENCE_INTEGRITY", stderr)

    def test_finalize_output_is_atomic_and_refuses_symlink(self) -> None:
        identity, expectation = self._identity(), self._expectation()
        source_document = support.without(support.synthetic_document(identity, expectation), "evidence_sha256")
        directory = Path(tempfile.mkdtemp())
        source_path = directory / "evidence.json"
        source_path.write_text(json.dumps(source_document), encoding="utf-8")
        output_path = directory / "finalized.json"
        code, stdout, stderr = run_finalize(["--evidence", str(source_path), "--output", str(output_path)])
        self.assertEqual(code, 0)
        self.assertEqual(stdout, "")
        written = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(written["evidence_sha256"], evidence_digest(source_document))
        leftovers = [entry.name for entry in directory.iterdir() if entry.name not in ("evidence.json", "finalized.json")]
        self.assertEqual(leftovers, [])
        link = directory / "linked.json"
        link.symlink_to(output_path)
        code, stdout, stderr = run_finalize(["--evidence", str(source_path), "--output", str(link)])
        self.assertEqual(code, 1)
        self.assertIn("EVIDENCE_INCOMPLETE", stderr)


if __name__ == "__main__":
    unittest.main()
