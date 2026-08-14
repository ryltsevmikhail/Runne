"""Fixture-only review closure over the existing verified RC0 subject graph."""
from __future__ import annotations

import hashlib
import json
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from scripts.rc0_policy.adjunct_schema_validation import validate_adjunct_schema_instance
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import PrincipalBinding, VerifiedEnvelope, require_fixture_verified
from scripts.rc0_policy.qualified_subject import QualifiedSubjectView

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ID = "gocode.rc0.production-security-review/1"
_TOKEN = object()
_CONTEXT_TOKEN = object()


class ProductionSecurityReviewFailure(ValueError): pass
def _fail(code: str) -> None: raise ProductionSecurityReviewFailure(code)
def _sha(value: bytes) -> str: return hashlib.sha256(value).hexdigest()
def _principal(envelope: VerifiedEnvelope) -> PrincipalBinding:
    return PrincipalBinding(envelope.issuer_role, envelope.issuer_subject_id, envelope.issuer_controlling_account_id, envelope.issuer_delegated_session_id, envelope.issuer_lane_id)


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class FixtureTrustedConsumptionContext:
    now_epoch_seconds: int; issuer_key_epoch: int; revocation_epoch: int
    _token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _CONTEXT_TOKEN or set(fields) != {"now_epoch_seconds", "issuer_key_epoch", "revocation_epoch"}: raise TypeError("FixtureTrustedConsumptionContext is verifier-owned")
        for name, value in fields.items(): object.__setattr__(self, name, value)
        object.__setattr__(self, "_token", token)
    def require_verified(self) -> None:
        values = (self.now_epoch_seconds, self.issuer_key_epoch, self.revocation_epoch)
        if type(self) is not FixtureTrustedConsumptionContext or self._token is not _CONTEXT_TOKEN or _CONTEXTS.get(self) != values or any(type(value) is not int or isinstance(value, bool) or value < 0 for value in values): _fail("CONSUMPTION_CONTEXT_INVALID")


_CONTEXTS: weakref.WeakKeyDictionary[FixtureTrustedConsumptionContext, tuple[int, int, int]] = weakref.WeakKeyDictionary()
def fixture_trusted_consumption_context(now_epoch_seconds: int, issuer_key_epoch: int, revocation_epoch: int) -> FixtureTrustedConsumptionContext:
    if any(type(value) is not int or isinstance(value, bool) or value < 0 for value in (now_epoch_seconds, issuer_key_epoch, revocation_epoch)): _fail("CONSUMPTION_CONTEXT_INVALID")
    context = FixtureTrustedConsumptionContext(_CONTEXT_TOKEN, now_epoch_seconds=now_epoch_seconds, issuer_key_epoch=issuer_key_epoch, revocation_epoch=revocation_epoch)
    _CONTEXTS[context] = (now_epoch_seconds, issuer_key_epoch, revocation_epoch); context.require_verified()
    return context
def _context(value: object) -> FixtureTrustedConsumptionContext:
    if type(value) is not FixtureTrustedConsumptionContext: _fail("CONSUMPTION_CONTEXT_INVALID")
    value.require_verified(); return value
def _envelope_current(envelope: VerifiedEnvelope, context: FixtureTrustedConsumptionContext) -> bool:
    return envelope.issuer_key_epoch == context.issuer_key_epoch and envelope.issuer_revocation_epoch == context.revocation_epoch and envelope.not_before_epoch_seconds <= envelope.issued_at_epoch_seconds <= context.now_epoch_seconds <= envelope.expires_at_epoch_seconds


def reviewed_closure_digest(subject: QualifiedSubjectView) -> str:
    """Domain-separated closure of the established, independently verified graph."""
    try: subject.require_verified(subject._subject_envelope.issued_at_epoch_seconds)
    except Exception as error: raise ProductionSecurityReviewFailure("REVIEW_SUBJECT_INVALID") from error
    evidence = sorted(digest for attestation in subject._attestations for digest in attestation.evidence_envelope_sha256s)
    value = {"outer_envelope_sha256s": [subject.envelope_sha256, subject.rc0_qualified_declaration_envelope_sha256, subject.rc0_verification_report_envelope_sha256, subject.mapping_policy_envelope_sha256, subject.active_activation_snapshot_envelope_sha256, *subject.attestation_envelope_sha256s, *evidence], "projections": {"required_gate_set_payload_sha256": subject.required_gate_set_payload_sha256, "artifact_set_payload_sha256": subject.artifact_set_payload_sha256, "profile_state_set_payload_sha256": subject.profile_state_set_payload_sha256, "normalized_platform_mapping_payload_sha256": subject.normalized_mapping_payload_sha256}}
    return _sha(b"gocode.rc0.reviewed-closure/1\0" + canonical_bytes(value))


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class VerifiedProductionSecurityReview:
    envelope_sha256: str; reviewed_closure_payload_sha256: str; reviewer_identity: PrincipalBinding
    _envelope: VerifiedEnvelope = field(repr=False, compare=False); _subject: QualifiedSubjectView = field(repr=False, compare=False); _context: FixtureTrustedConsumptionContext = field(repr=False, compare=False); _token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_token"}: raise TypeError("VerifiedProductionSecurityReview is verifier-owned")
        for name, value in fields.items(): object.__setattr__(self, name, value)
        object.__setattr__(self, "_token", token)
    def require_verified(self, context: FixtureTrustedConsumptionContext) -> None:
        state = _ISSUED.get(self)
        if type(self) is not VerifiedProductionSecurityReview or self._token is not _TOKEN or state is None or context is not state[2] or (self._envelope, self._subject, self._context) != state: _fail("REVIEW_CONTEXT_INVALID")
        payload, identity = _verify(*state)
        if (self.envelope_sha256, self.reviewed_closure_payload_sha256, self.reviewer_identity) != (state[0].envelope_sha256, payload["reviewed_closure_payload_sha256"], identity): _fail("REVIEW_CONTEXT_INVALID")


_ISSUED: weakref.WeakKeyDictionary[VerifiedProductionSecurityReview, tuple[VerifiedEnvelope, QualifiedSubjectView, FixtureTrustedConsumptionContext]] = weakref.WeakKeyDictionary()


def _verify(envelope: object, subject: object, context: object) -> tuple[dict[str, object], PrincipalBinding]:
    if type(envelope) is not VerifiedEnvelope or type(subject) is not QualifiedSubjectView: _fail("REVIEW_INPUT_INVALID")
    try: require_fixture_verified(envelope); payload = loads_canonical(envelope.payload_canonical_bytes); schema = json.loads((ROOT / "docs/schemas/rc0-production-security-review-v1.schema.json").read_bytes())
    except Exception as error: raise ProductionSecurityReviewFailure("REVIEW_CONTEXT_INVALID") from error
    if envelope.payload_schema_id != SCHEMA_ID or validate_adjunct_schema_instance(schema, payload): _fail("REVIEW_SCHEMA_INVALID")
    identity = _principal(envelope); reviewer = payload.get("reviewer")
    expected = (identity.role_id, identity.subject_id, identity.controlling_account_id, identity.delegated_session_id, identity.lane_id)
    if type(reviewer) is not dict or payload.get("issuer") != reviewer or tuple(reviewer.get(key) for key in ("role_id", "subject_id", "controlling_account_id", "delegated_session_id", "lane_id")) != expected or identity.role_id != "production_security_reviewer": _fail("REVIEW_PRINCIPAL_INVALID")
    inherited = [subject.issuer_identity, subject._declaration.declarer_identity, subject._report.reporter_identity, subject._mapping.mapping_authority, subject._activation.policy_authority_identity]
    for attestation in subject._attestations: inherited.extend((attestation.attestation_issuer_identity, attestation.host.host_attestor_identity, *attestation.evidence_identities))
    if any(identity == item or any(getattr(identity, part) == getattr(item, part) for part in ("subject_id", "controlling_account_id", "delegated_session_id", "lane_id")) for item in inherited if item is not None): _fail("REVIEW_PRINCIPAL_INVALID")
    context = _context(context)
    try: subject.require_verified(context.now_epoch_seconds)
    except Exception as error: raise ProductionSecurityReviewFailure("REVIEW_CONTEXT_INVALID") from error
    times = ("issued_at", "not_before", "expires_at")
    if payload.get("issuer_key_id") != envelope.issuer_key_id or payload.get("issuer_key_epoch") != envelope.issuer_key_epoch or payload.get("revocation_epoch") != envelope.issuer_revocation_epoch or payload.get("signature_profile_id") != envelope.signature_profile_id or any(payload.get(name) != getattr(envelope, name) for name in times) or not _envelope_current(envelope, context) or payload.get("reviewed_closure_payload_sha256") != reviewed_closure_digest(subject): _fail("REVIEW_CONTEXT_INVALID")
    return payload, identity


def verify_production_security_review(envelope: VerifiedEnvelope, subject: QualifiedSubjectView, context: FixtureTrustedConsumptionContext) -> VerifiedProductionSecurityReview:
    payload, identity = _verify(envelope, subject, context)
    view = VerifiedProductionSecurityReview(_TOKEN, envelope_sha256=envelope.envelope_sha256, reviewed_closure_payload_sha256=payload["reviewed_closure_payload_sha256"], reviewer_identity=identity, _envelope=envelope, _subject=subject, _context=context)
    _ISSUED[view] = (envelope, subject, context); view.require_verified(context)
    return view


def validate_production_security_review(*_: object, **__: object) -> None: _fail("SUPERSEDED_SURROGATE_UNSUPPORTED")
