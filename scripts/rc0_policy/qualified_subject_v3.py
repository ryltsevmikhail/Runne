"""One-way, non-authorizing V3 RC0 handoff over actual verified predecessor views."""
from __future__ import annotations

import hashlib
import json
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from scripts.rc0_policy.adjunct_schema_validation import validate_adjunct_schema_instance
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import PrincipalBinding, VerifiedEnvelope, require_fixture_verified
from scripts.rc0_policy.platform_matrix import normalized_platform_mapping_payload
from scripts.rc0_policy.production_security_review import FixtureTrustedConsumptionContext, VerifiedProductionSecurityReview, _context, _envelope_current
from scripts.rc0_policy.qualified_subject import QualifiedSubjectView

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ID = "gocode.rc0.platform-qualified-subject/3"
_TOKEN = object()


class QualifiedSubjectV3Failure(ValueError): pass
def _fail(code: str) -> None: raise QualifiedSubjectV3Failure(code)
def _principal(value: VerifiedEnvelope) -> PrincipalBinding: return PrincipalBinding(value.issuer_role, value.issuer_subject_id, value.issuer_controlling_account_id, value.issuer_delegated_session_id, value.issuer_lane_id)
def _sha(value: bytes) -> str: return hashlib.sha256(value).hexdigest()
def _release_artifact_closure(predecessor: QualifiedSubjectView) -> bytes:
    try:
        closure = normalized_platform_mapping_payload(predecessor._attestations)
        if canonical_bytes(loads_canonical(closure)) != closure: raise ValueError
        return closure
    except Exception as error: raise QualifiedSubjectV3Failure("HANDOFF_CLOSURE_INVALID") from error


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class VerifiedRc0HandoffV3:
    envelope_sha256: str; predecessor_subject_envelope_sha256: str; normalized_platform_mapping_payload_sha256: str; normalized_release_artifact_closure_payload_sha256: str; normalized_release_artifact_closure_payload: bytes
    _envelope: VerifiedEnvelope = field(repr=False, compare=False); _predecessor: QualifiedSubjectView = field(repr=False, compare=False); _review: VerifiedProductionSecurityReview = field(repr=False, compare=False); _context: FixtureTrustedConsumptionContext = field(repr=False, compare=False); _token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_token"}: raise TypeError("VerifiedRc0HandoffV3 is verifier-owned")
        for name, value in fields.items(): object.__setattr__(self, name, value)
        object.__setattr__(self, "_token", token)
    def require_verified(self, context: FixtureTrustedConsumptionContext) -> None:
        state = _ISSUED.get(self)
        if type(self) is not VerifiedRc0HandoffV3 or self._token is not _TOKEN or state is None or context is not state[3] or (self._envelope, self._predecessor, self._review, self._context) != state: _fail("HANDOFF_HANDLE_INVALID")
        payload = _verify(*state)
        closure = _release_artifact_closure(state[1])
        expected = (state[0].envelope_sha256, payload["predecessor_subject_envelope_sha256"], payload["normalized_platform_mapping_payload_sha256"], payload["normalized_release_artifact_closure_payload_sha256"], closure)
        if _sha(closure) != payload["normalized_release_artifact_closure_payload_sha256"] or (self.envelope_sha256, self.predecessor_subject_envelope_sha256, self.normalized_platform_mapping_payload_sha256, self.normalized_release_artifact_closure_payload_sha256, self.normalized_release_artifact_closure_payload) != expected: _fail("HANDOFF_HANDLE_INVALID")


_ISSUED: weakref.WeakKeyDictionary[VerifiedRc0HandoffV3, tuple[VerifiedEnvelope, QualifiedSubjectView, VerifiedProductionSecurityReview, FixtureTrustedConsumptionContext]] = weakref.WeakKeyDictionary()


def _verify(envelope: object, predecessor: object, review: object, context: object) -> dict[str, object]:
    if type(envelope) is not VerifiedEnvelope or type(predecessor) is not QualifiedSubjectView or type(review) is not VerifiedProductionSecurityReview: _fail("HANDOFF_INPUT_INVALID")
    context = _context(context)
    try: predecessor.require_verified(context.now_epoch_seconds); review.require_verified(context); require_fixture_verified(envelope); payload = loads_canonical(envelope.payload_canonical_bytes); schema = json.loads((ROOT / "docs/schemas/rc0-platform-qualified-subject-v3.schema.json").read_bytes())
    except Exception as error: raise QualifiedSubjectV3Failure("HANDOFF_CONTEXT_INVALID") from error
    if review._subject is not predecessor: _fail("HANDOFF_CONTEXT_INVALID")
    if envelope.payload_schema_id != SCHEMA_ID or validate_adjunct_schema_instance(schema, payload): _fail("HANDOFF_SCHEMA_INVALID")
    identity = _principal(envelope)
    if _principal(envelope) != predecessor.issuer_identity or payload.get("issuer") != {"role_id": identity.role_id, "subject_id": identity.subject_id, "controlling_account_id": identity.controlling_account_id, "delegated_session_id": identity.delegated_session_id, "lane_id": identity.lane_id}: _fail("HANDOFF_PRINCIPAL_INVALID")
    closure = _release_artifact_closure(predecessor)
    exact = {"predecessor_subject_envelope_sha256": predecessor.envelope_sha256, "production_security_review_envelope_sha256": review.envelope_sha256, "reviewed_closure_payload_sha256": review.reviewed_closure_payload_sha256, "rc0_qualified_declaration_envelope_sha256": predecessor.rc0_qualified_declaration_envelope_sha256, "rc0_verification_report_envelope_sha256": predecessor.rc0_verification_report_envelope_sha256, "mapping_policy_envelope_sha256": predecessor.mapping_policy_envelope_sha256, "active_activation_snapshot_envelope_sha256": predecessor.active_activation_snapshot_envelope_sha256, "platform_attestation_envelope_sha256s": list(predecessor.attestation_envelope_sha256s), "normalized_platform_mapping_payload_sha256": predecessor.normalized_mapping_payload_sha256, "normalized_release_artifact_closure_payload_sha256": _sha(closure), "required_gate_set_payload_sha256": predecessor.required_gate_set_payload_sha256, "artifact_set_payload_sha256": predecessor.artifact_set_payload_sha256, "profile_state_set_payload_sha256": predecessor.profile_state_set_payload_sha256}
    if any(payload.get(name) != value for name, value in exact.items()) or payload.get("issuer_key_epoch") != envelope.issuer_key_epoch or payload.get("revocation_epoch") != envelope.issuer_revocation_epoch or not _envelope_current(envelope, context): _fail("HANDOFF_BINDING_INVALID")
    return payload


def verify_qualified_subject_v3(envelope: VerifiedEnvelope, predecessor: QualifiedSubjectView, review: VerifiedProductionSecurityReview, context: FixtureTrustedConsumptionContext) -> VerifiedRc0HandoffV3:
    payload = _verify(envelope, predecessor, review, context)
    closure = _release_artifact_closure(predecessor)
    view = VerifiedRc0HandoffV3(_TOKEN, envelope_sha256=envelope.envelope_sha256, predecessor_subject_envelope_sha256=payload["predecessor_subject_envelope_sha256"], normalized_platform_mapping_payload_sha256=payload["normalized_platform_mapping_payload_sha256"], normalized_release_artifact_closure_payload_sha256=payload["normalized_release_artifact_closure_payload_sha256"], normalized_release_artifact_closure_payload=closure, _envelope=envelope, _predecessor=predecessor, _review=review, _context=context)
    _ISSUED[view] = (envelope, predecessor, review, context); view.require_verified(context)
    return view


def reviewed_closure_digest(subject: QualifiedSubjectView) -> str:
    from scripts.rc0_policy.production_security_review import reviewed_closure_digest as closure
    return closure(subject)


def validate_qualified_subject_v3(*_: object, **__: object) -> None: _fail("SUPERSEDED_SURROGATE_UNSUPPORTED")
def verify_qualified_subject_v3_production(*_: object, **__: object) -> None: _fail("PRODUCTION_AUTHENTICATOR_NOT_PROVISIONED")
