"""RC0 V3 handoff consumes the existing verified RC0 graph, never surrogates."""
from __future__ import annotations

import hashlib
import unittest
from dataclasses import FrozenInstanceError

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, verify_signed_envelope
from scripts.rc0_policy.platform_matrix import normalized_platform_mapping_payload
from scripts.rc0_policy.platform_matrix_v4 import VerifiedPlatformMatrixV4, verify_platform_matrix_v4
from scripts.rc0_policy.production_security_review import VerifiedProductionSecurityReview, fixture_trusted_consumption_context, verify_production_security_review
from scripts.rc0_policy.qualified_subject import fixture_verify_qualified_subject
from scripts.rc0_policy.qualified_subject_v3 import VerifiedRc0HandoffV3, reviewed_closure_digest, verify_qualified_subject_v3
from scripts.tests.rc0_platform_envelope_support import _fixture_envelope, _fixture_schema_store, _sign, valid_fixture_envelope
from scripts.tests.rc0_platform_subject_support import valid_subject_fixture


ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
NOW = 1_700_000_000
REVIEWER = {
    "role_id": "production_security_reviewer", "subject_id": "reviewer-subject",
    "controlling_account_id": "reviewer-account", "delegated_session_id": "reviewer-session", "lane_id": "reviewer-lane",
}


def _digest(value: object) -> str: return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _outer(schema: str, payload: dict[str, object], identity: dict[str, str], *, revocation: int = 3):
    docs = dict(_fixture_schema_store()._schemas)
    docs[schema] = (ROOT / "docs/schemas" / {
        "gocode.rc0.production-security-review/1": "rc0-production-security-review-v1.schema.json",
        "gocode.rc0.platform-qualified-subject/3": "rc0-platform-qualified-subject-v3.schema.json",
        "gocode.release.platform-qualification-matrix/4": "release-platform-qualification-matrix-v4.schema.json",
    }[schema]).read_bytes()
    outer = _fixture_envelope(payload)
    outer.update(payload_schema_id=schema, payload_schema_sha256=hashlib.sha256(docs[schema]).hexdigest(), payload_sha256=_digest(payload), issuer_role=identity["role_id"], issuer_subject_id=identity["subject_id"], issuer_controlling_account_id=identity["controlling_account_id"], issuer_delegated_session_id=identity["delegated_session_id"], issuer_lane_id=identity["lane_id"], issuer_key_id=identity["role_id"] + "-key", issuer_revocation_epoch=revocation)
    _, verifier = valid_fixture_envelope()
    return verify_signed_envelope(_sign(outer), AdjunctSchemaStore(docs), verifier, NOW)


def _review_payload(subject: object) -> dict[str, object]:
    closure = reviewed_closure_digest(subject)
    return {"schema_version": "gocode.rc0.production-security-review/1", "repository_id": "gocode", "review_state": "APPROVED", "reviewer": REVIEWER, "issuer": REVIEWER, "reviewed_closure_payload_sha256": closure, "issuer_key_id": "production_security_reviewer-key", "issuer_key_epoch": 7, "revocation_epoch": 3, "signature_profile_id": "FIXTURE_ONLY", "issued_at": "2023-11-14T22:13:20Z", "not_before": "2023-11-14T22:13:10Z", "expires_at": "2023-11-14T22:13:30Z"}


def _v3_payload(subject: object, review: object) -> dict[str, object]:
    issuer = {"role_id": subject.issuer_identity.role_id, "subject_id": subject.issuer_identity.subject_id, "controlling_account_id": subject.issuer_identity.controlling_account_id, "delegated_session_id": subject.issuer_identity.delegated_session_id, "lane_id": subject.issuer_identity.lane_id}
    closure = normalized_platform_mapping_payload(subject._attestations)
    return {"schema_version": "gocode.rc0.platform-qualified-subject/3", "repository_id": "gocode", "issuer": issuer, "predecessor_subject_envelope_sha256": subject.envelope_sha256, "production_security_review_envelope_sha256": review.envelope_sha256, "reviewed_closure_payload_sha256": review.reviewed_closure_payload_sha256, "rc0_qualified_declaration_envelope_sha256": subject.rc0_qualified_declaration_envelope_sha256, "rc0_verification_report_envelope_sha256": subject.rc0_verification_report_envelope_sha256, "mapping_policy_envelope_sha256": subject.mapping_policy_envelope_sha256, "active_activation_snapshot_envelope_sha256": subject.active_activation_snapshot_envelope_sha256, "platform_attestation_envelope_sha256s": list(subject.attestation_envelope_sha256s), "normalized_platform_mapping_payload_sha256": subject.normalized_mapping_payload_sha256, "normalized_release_artifact_closure_payload_sha256": hashlib.sha256(closure).hexdigest(), "required_gate_set_payload_sha256": subject.required_gate_set_payload_sha256, "artifact_set_payload_sha256": subject.artifact_set_payload_sha256, "profile_state_set_payload_sha256": subject.profile_state_set_payload_sha256, "issuer_key_epoch": 7, "revocation_epoch": 3}


class Rc0HandoffV3Tests(unittest.TestCase):
    def _verified(self):
        context = fixture_trusted_consumption_context(NOW, 7, 3)
        fixture = valid_subject_fixture(); subject = fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, NOW)
        review = verify_production_security_review(_outer("gocode.rc0.production-security-review/1", _review_payload(subject), REVIEWER), subject, context)
        handoff = verify_qualified_subject_v3(_outer("gocode.rc0.platform-qualified-subject/3", _v3_payload(subject, review), {"role_id": subject.issuer_identity.role_id, "subject_id": subject.issuer_identity.subject_id, "controlling_account_id": subject.issuer_identity.controlling_account_id, "delegated_session_id": subject.issuer_identity.delegated_session_id, "lane_id": subject.issuer_identity.lane_id}), subject, review, context)
        return subject, review, handoff, context

    def test_real_verified_graph_closes_one_way(self) -> None:
        subject, _, handoff, context = self._verified()
        issuer = {"role_id": subject.issuer_identity.role_id, "subject_id": subject.issuer_identity.subject_id, "controlling_account_id": subject.issuer_identity.controlling_account_id, "delegated_session_id": subject.issuer_identity.delegated_session_id, "lane_id": subject.issuer_identity.lane_id}
        matrix_payload = {"schema_version": "gocode.release.platform-qualification-matrix/4", "repository_id": "gocode", "issuer": issuer, "platform_qualified_subject_envelope_sha256": handoff.envelope_sha256, "predecessor_subject_envelope_sha256": subject.envelope_sha256, "normalized_platform_mapping_payload_sha256": handoff.normalized_platform_mapping_payload_sha256, "issuer_key_epoch": 7, "revocation_epoch": 3}
        matrix = verify_platform_matrix_v4(_outer("gocode.release.platform-qualification-matrix/4", matrix_payload, issuer), handoff, context)
        self.assertEqual(matrix.normalized_platform_mapping_payload_sha256, handoff.normalized_platform_mapping_payload_sha256)

    def test_rejects_missing_or_foreign_or_expired_evidence(self) -> None:
        subject, review, _, context = self._verified()
        with self.assertRaisesRegex(ValueError, "SCHEMA_INVALID"):
            verify_production_security_review(_outer("gocode.rc0.production-security-review/1", {}, REVIEWER), subject, context)
        foreign = dict(REVIEWER); foreign["lane_id"] = subject.issuer_identity.lane_id
        with self.assertRaisesRegex(ValueError, "REVIEW_PRINCIPAL_INVALID"):
            verify_production_security_review(_outer("gocode.rc0.production-security-review/1", _review_payload(subject), foreign), subject, context)
        for stale_context in (fixture_trusted_consumption_context(NOW, 8, 3), fixture_trusted_consumption_context(NOW, 7, 4)):
            with self.subTest(context=stale_context):
                with self.assertRaisesRegex(ValueError, "REVIEW_CONTEXT_INVALID"):
                    verify_production_security_review(_outer("gocode.rc0.production-security-review/1", _review_payload(subject), REVIEWER), subject, stale_context)
        for field, value in (("issued_at", "2023-11-14T22:13:19Z"), ("not_before", "2023-11-14T22:13:09Z"), ("expires_at", "2023-11-14T22:13:29Z")):
            with self.subTest(field=field):
                payload = _review_payload(subject); payload[field] = value
                with self.assertRaisesRegex(ValueError, "REVIEW_CONTEXT_INVALID"):
                    verify_production_security_review(_outer("gocode.rc0.production-security-review/1", payload, REVIEWER), subject, context)
        payload = _review_payload(subject); payload["issued_at"] = "2023-11-14T22:13:20+00:00"
        with self.assertRaisesRegex(ValueError, "SCHEMA_INVALID"):
            verify_production_security_review(_outer("gocode.rc0.production-security-review/1", payload, REVIEWER), subject, context)
        payload = _v3_payload(subject, review); payload["required_gate_set_payload_sha256"] = "f" * 64
        identity = {"role_id": subject.issuer_identity.role_id, "subject_id": subject.issuer_identity.subject_id, "controlling_account_id": subject.issuer_identity.controlling_account_id, "delegated_session_id": subject.issuer_identity.delegated_session_id, "lane_id": subject.issuer_identity.lane_id}
        with self.assertRaisesRegex(ValueError, "HANDOFF_BINDING_INVALID"):
            verify_qualified_subject_v3(_outer("gocode.rc0.platform-qualified-subject/3", payload, identity), subject, review, context)
        other = valid_subject_fixture(); other_subject = fixture_verify_qualified_subject(other.subject, other.declaration, other.report, other.mapping, other.activation, other.attestations, NOW)
        other_payload = _v3_payload(other_subject, review)
        other_identity = {"role_id": other_subject.issuer_identity.role_id, "subject_id": other_subject.issuer_identity.subject_id, "controlling_account_id": other_subject.issuer_identity.controlling_account_id, "delegated_session_id": other_subject.issuer_identity.delegated_session_id, "lane_id": other_subject.issuer_identity.lane_id}
        with self.assertRaisesRegex(ValueError, "HANDOFF_CONTEXT_INVALID"):
            verify_qualified_subject_v3(_outer("gocode.rc0.platform-qualified-subject/3", other_payload, other_identity), other_subject, review, context)
        with self.assertRaisesRegex(ValueError, "REVIEW_CONTEXT_INVALID"):
            review.require_verified(fixture_trusted_consumption_context(1_700_000_100, 7, 3))

    def test_sealed_handles_are_distinct_and_non_authorizing(self) -> None:
        _, review, handoff, _ = self._verified()
        with self.assertRaises(TypeError): VerifiedProductionSecurityReview()  # type: ignore[call-arg]
        with self.assertRaises(TypeError): VerifiedRc0HandoffV3()  # type: ignore[call-arg]
        with self.assertRaises(TypeError): VerifiedPlatformMatrixV4()  # type: ignore[call-arg]
        with self.assertRaises(FrozenInstanceError): handoff.envelope_sha256 = "f" * 64  # type: ignore[misc]
        self.assertFalse(hasattr(review, "authorizes_production")); self.assertFalse(hasattr(handoff, "authorizes_production"))

    def test_public_projections_tampered_after_verification_reject(self) -> None:
        fields = (("review", "envelope_sha256"), ("review", "reviewed_closure_payload_sha256"), ("handoff", "envelope_sha256"), ("handoff", "normalized_platform_mapping_payload_sha256"), ("handoff", "normalized_release_artifact_closure_payload_sha256"), ("handoff", "normalized_release_artifact_closure_payload"), ("matrix", "envelope_sha256"), ("matrix", "normalized_platform_mapping_payload_sha256"))
        for target, field in fields:
            with self.subTest(view=target, field=field):
                subject, review, handoff, context = self._verified()
                identity = {"role_id": subject.issuer_identity.role_id, "subject_id": subject.issuer_identity.subject_id, "controlling_account_id": subject.issuer_identity.controlling_account_id, "delegated_session_id": subject.issuer_identity.delegated_session_id, "lane_id": subject.issuer_identity.lane_id}
                matrix_payload = {"schema_version": "gocode.release.platform-qualification-matrix/4", "repository_id": "gocode", "issuer": identity, "platform_qualified_subject_envelope_sha256": handoff.envelope_sha256, "predecessor_subject_envelope_sha256": subject.envelope_sha256, "normalized_platform_mapping_payload_sha256": handoff.normalized_platform_mapping_payload_sha256, "issuer_key_epoch": 7, "revocation_epoch": 3}
                matrix = verify_platform_matrix_v4(_outer("gocode.release.platform-qualification-matrix/4", matrix_payload, identity), handoff, context)
                if target == "handoff":
                    closure = loads_canonical(handoff.normalized_release_artifact_closure_payload)
                    self.assertEqual(closure["cells"][0]["artifact_rows"][0]["artifact_slot_id"], "linux-appimage")
                    self.assertEqual(closure["cells"][0]["architecture"], "x86_64")
                    self.assertIn("profile_rows", closure["cells"][0])
                view = {"review": review, "handoff": handoff, "matrix": matrix}[target]
                object.__setattr__(view, field, b"{}" if field.endswith("payload") else "f" * 64)
                with self.assertRaises(ValueError):
                    view.require_verified(context)


if __name__ == "__main__": unittest.main()
