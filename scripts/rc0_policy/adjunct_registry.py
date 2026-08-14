"""Opaque verification view for the closed post-RC0 adjunct registry."""

from __future__ import annotations

import weakref
from dataclasses import dataclass, field
from typing import Literal

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import (
    AdjunctSchemaStore, EnvelopeFailure, FIXTURE_ONLY, PRODUCTION, PrincipalBinding,
    TrustVerification, VerifiedEnvelope, principal_binding, sha256_digest,
    signature_transcript, timestamp_epoch_seconds,
)


REGISTRY_SCHEMA_ID = "gocode.rc0.post-rc0-adjunct-trust-schema-registry/1"
REGISTRY_AUTHORITY = "POST_RC0_ADJUNCT_REGISTRY_AUTHORITY"
RECEIPT_AUTHORITY = "POST_RC0_G1_RECEIPT_AUTHORITY"
RECONCILIATION_AUTHORITY = "POST_RC0_RECONCILIATION_AUTHORITY"
_EXPECTED_SCHEMA_IDS = frozenset((
    "gocode.external-signed-envelope/1", "gocode.governance.platform-decision-acceptance/1",
    "gocode.rc0.platform-scope-mapping-policy/1", "gocode.rc0.qualified-declaration/1",
    "gocode.rc0.platform-scope-attestation/1", "gocode.rc0.artifact-measurement-record/1",
    "gocode.rc0.native-host-evidence-record/1", "gocode.rc0.profile-evidence-record/1",
    "gocode.rc0.canary-evidence-record/1", "gocode.rc0.policy-activation-intent/1",
    "gocode.rc0.policy-acceptance-receipt/1", "gocode.rc0.policy-activation-snapshot/1",
    "gocode.rc0.platform-qualified-subject/1", "gocode.release.platform-qualification-matrix/2",
    "gocode.rc0.post-rc0-owner-authority-receipt/1", "gocode.v1-platform-scope-claim-migration/1",
    "gocode.rc0.post-rc0-platform-composed-universe/1", "gocode.rc0.post-rc0-reconciliation-receipt/1",
))
_EXPECTED_ROLES = frozenset((
    REGISTRY_AUTHORITY, RECEIPT_AUTHORITY, RECONCILIATION_AUTHORITY,
    "runtime_platform_owner", "desktop_platform_owner", "mapping_policy_authority",
    "rc0_qualification_reporter", "rc0_qualification_declarer", "artifact_classifier_a",
    "artifact_classifier_b", "native_host_attestor", "external_canary_operator",
    "qualification_aggregator", "policy_authority",
))
_TOKEN = object()


class AdjunctRegistryFailure(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, init=False, slots=True, weakref_slot=True)
class VerifiedAdjunctTrustRegistry:
    envelope_sha256: str
    payload_sha256: str
    envelope_canonical_bytes: bytes
    payload_canonical_bytes: bytes
    verification_domain: Literal["FIXTURE_ONLY", "PRODUCTION"]
    trust: TrustVerification
    issued_at_epoch_seconds: int
    expires_at_epoch_seconds: int
    revocation_epoch: int
    adjunct_schema_digests: tuple[tuple[str, str], ...]
    role_principal_constraints: tuple[tuple[str, PrincipalBinding], ...]
    registry_authority: PrincipalBinding
    receipt_authority: PrincipalBinding
    reconciliation_authority: PrincipalBinding
    _verification_token: object = field(repr=False, compare=False)

    def __init__(self, verification_token: object, /, **fields: object) -> None:
        if verification_token is not _TOKEN:
            raise TypeError("VerifiedAdjunctTrustRegistry is verifier-owned")
        if set(fields) != set(self.__dataclass_fields__) - {"_verification_token"}:
            raise TypeError("VerifiedAdjunctTrustRegistry requires verified fields")
        for name, value in fields.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_verification_token", verification_token)

    def require_verified(self, now_epoch_seconds: int) -> None:
        state = _state(self)
        if type(self) is not VerifiedAdjunctTrustRegistry or self._verification_token is not _TOKEN or state is None or self.envelope_canonical_bytes is not state.envelope or self.payload_canonical_bytes is not state.payload or self.trust is not state.trust:
            raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
        try:
            if _fingerprint(self) != state.fingerprint: raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
            envelope = loads_canonical(self.envelope_canonical_bytes)
            payload = loads_canonical(self.payload_canonical_bytes)
            _verify_view(self, envelope, payload, now_epoch_seconds)
        except (EnvelopeFailure, TypeError, ValueError) as error:
            if isinstance(error, AdjunctRegistryFailure):
                raise
            raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID") from error

    def _require_verified(self, now_epoch_seconds: int) -> None:
        VerifiedAdjunctTrustRegistry.require_verified(self, now_epoch_seconds)


@dataclass(frozen=True)
class _RegistryState:
    reference: weakref.ReferenceType[VerifiedAdjunctTrustRegistry]; envelope: bytes; payload: bytes
    trust: TrustVerification; fingerprint: str
_STATES: dict[int, _RegistryState] = {}
def _state(view: VerifiedAdjunctTrustRegistry) -> _RegistryState | None:
    state = _STATES.get(id(view)); return state if state is not None and state.reference() is view else None
def _remember(view: VerifiedAdjunctTrustRegistry, envelope: bytes, payload: bytes, trust: TrustVerification, fingerprint: str) -> None:
    identity = id(view)
    def forget(reference: weakref.ReferenceType[VerifiedAdjunctTrustRegistry]) -> None:
        if (state := _STATES.get(identity)) is not None and state.reference is reference: _STATES.pop(identity, None)
    _STATES[identity] = _RegistryState(weakref.ref(view, forget), envelope, payload, trust, fingerprint)


def _principal_fields(value: object) -> list[str]:
    if type(value) is not PrincipalBinding or any(type(item) is not str for item in (value.role_id, value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id)): raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    return [value.role_id, value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id]
def _trust_fields(value: object) -> list[object]:
    if type(value) is not TrustVerification or any(type(item) is not str for item in (value.verification_domain, value.transcript_sha256, value.issuer, value.issuer_key_id, value.signature_profile_id)) or type(value.issuer_key_epoch) is not int or type(value.issuer_revocation_epoch) is not int: raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    return [value.verification_domain, value.transcript_sha256, value.issuer, value.issuer_key_id, value.issuer_key_epoch, value.issuer_revocation_epoch, value.signature_profile_id, _principal_fields(value.principal)]
def _fingerprint(view: VerifiedAdjunctTrustRegistry) -> str:
    schemas, roles = view.adjunct_schema_digests, view.role_principal_constraints
    if any(type(item) is not str for item in (view.envelope_sha256, view.payload_sha256, view.verification_domain)) or type(view.envelope_canonical_bytes) is not bytes or type(view.payload_canonical_bytes) is not bytes or view.verification_domain not in {FIXTURE_ONLY, PRODUCTION} or any(type(item) is not int for item in (view.issued_at_epoch_seconds, view.expires_at_epoch_seconds, view.revocation_epoch)) or type(schemas) is not tuple or type(roles) is not tuple: raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    if any(type(pair) is not tuple or len(pair) != 2 or any(type(item) is not str for item in pair) for pair in schemas) or any(type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str for pair in roles): raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    return sha256_digest(canonical_bytes({"hashes": [view.envelope_sha256, view.payload_sha256, sha256_digest(view.envelope_canonical_bytes), sha256_digest(view.payload_canonical_bytes)], "domain": view.verification_domain, "trust": _trust_fields(view.trust), "times": [view.issued_at_epoch_seconds, view.expires_at_epoch_seconds, view.revocation_epoch], "schemas": [list(pair) for pair in schemas], "roles": [[role, _principal_fields(principal)] for role, principal in roles], "authorities": [_principal_fields(view.registry_authority), _principal_fields(view.receipt_authority), _principal_fields(view.reconciliation_authority)]}))


def _schema_digests(payload: dict[str, object]) -> tuple[tuple[str, str], ...]:
    values = payload.get("adjunct_schema_digests")
    if type(values) is not list:
        raise AdjunctRegistryFailure("REGISTRY_SCHEMA_SET_INVALID")
    result: list[tuple[str, str]] = []
    for item in values:
        if type(item) is not dict or set(item) != {"schema_id", "schema_sha256"}:
            raise AdjunctRegistryFailure("REGISTRY_SCHEMA_SET_INVALID")
        schema_id, digest = item["schema_id"], item["schema_sha256"]
        if type(schema_id) is not str or type(digest) is not str:
            raise AdjunctRegistryFailure("REGISTRY_SCHEMA_SET_INVALID")
        result.append((schema_id, digest))
    frozen = tuple(result)
    if frozen != tuple(sorted(frozen)) or len(set(frozen)) != len(frozen) or {key for key, _ in frozen} != _EXPECTED_SCHEMA_IDS:
        raise AdjunctRegistryFailure("REGISTRY_SCHEMA_SET_INVALID")
    return frozen


def _constraints(payload: dict[str, object]) -> tuple[tuple[str, PrincipalBinding], ...]:
    values = payload.get("role_principal_constraints")
    if type(values) is not list:
        raise AdjunctRegistryFailure("REGISTRY_ROLE_CONSTRAINTS_INVALID")
    result: list[tuple[str, PrincipalBinding]] = []
    components: list[str] = []
    for item in values:
        if type(item) is not dict or set(item) != {"role_id", "principal"} or type(item["role_id"]) is not str:
            raise AdjunctRegistryFailure("REGISTRY_ROLE_CONSTRAINTS_INVALID")
        principal = item["principal"]
        fields = ("subject_id", "controlling_account_id", "delegated_session_id", "lane_id")
        if type(principal) is not dict or set(principal) != set(fields) or any(type(principal[key]) is not str or not principal[key] for key in fields):
            raise AdjunctRegistryFailure("REGISTRY_ROLE_CONSTRAINTS_INVALID")
        components.extend(principal[key] for key in fields)
        result.append((item["role_id"], PrincipalBinding(item["role_id"], **principal)))
    frozen = tuple(result)
    if frozen != tuple(sorted(frozen, key=lambda item: item[0])) or {role for role, _ in frozen} != _EXPECTED_ROLES:
        raise AdjunctRegistryFailure("REGISTRY_ROLE_CONSTRAINTS_INVALID")
    if len(set(components)) != len(components):
        raise AdjunctRegistryFailure("REGISTRY_PRINCIPAL_OVERLAP")
    return frozen


def _view_payload(view: VerifiedAdjunctTrustRegistry, payload: dict[str, object]) -> None:
    if canonical_bytes(payload) != view.payload_canonical_bytes or sha256_digest(view.payload_canonical_bytes) != view.payload_sha256:
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    if _schema_digests(payload) != view.adjunct_schema_digests or _constraints(payload) != view.role_principal_constraints:
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    if payload.get("revocation_epoch") != view.revocation_epoch or view.revocation_epoch != view.trust.issuer_revocation_epoch:
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")


def _verify_view(view: VerifiedAdjunctTrustRegistry, envelope: object, payload: object, now: int) -> None:
    if type(envelope) is not dict or type(payload) is not dict or type(now) is not int or isinstance(now, bool):
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    if sha256_digest(view.envelope_canonical_bytes) != view.envelope_sha256 or canonical_bytes(envelope) != view.envelope_canonical_bytes or envelope.get("payload") != payload or envelope.get("payload_sha256") != view.payload_sha256:
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    if envelope.get("payload_schema_id") != REGISTRY_SCHEMA_ID or view.verification_domain not in {FIXTURE_ONLY, PRODUCTION}:
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    issued, expires, not_before = (timestamp_epoch_seconds(envelope.get(name)) for name in ("issued_at", "expires_at", "not_before"))
    if issued != view.issued_at_epoch_seconds or expires != view.expires_at_epoch_seconds or not not_before <= issued <= now <= expires:
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    principal = PrincipalBinding(envelope.get("issuer_role"), envelope.get("issuer_subject_id"), envelope.get("issuer_controlling_account_id"), envelope.get("issuer_delegated_session_id"), envelope.get("issuer_lane_id"))
    expected_domain = FIXTURE_ONLY if envelope.get("issuer") == FIXTURE_ONLY else PRODUCTION
    if type(view.trust) is not TrustVerification or view.verification_domain != expected_domain or view.trust.verification_domain != expected_domain or view.trust.principal != principal or view.trust.issuer != envelope.get("issuer") or view.trust.issuer_key_id != envelope.get("issuer_key_id") or view.trust.issuer_key_epoch != envelope.get("issuer_key_epoch") or view.trust.issuer_revocation_epoch != envelope.get("issuer_revocation_epoch") or view.trust.signature_profile_id != envelope.get("signature_profile_id"):
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    unsigned = dict(envelope)
    signature = unsigned.pop("signature", None)
    if type(signature) is not str or view.trust.transcript_sha256 != sha256_digest(signature_transcript(unsigned)):
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    if payload.get("issued_at") != envelope.get("issued_at") or payload.get("expires_at") != envelope.get("expires_at"):
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    _view_payload(view, payload)
    authorities = dict(view.role_principal_constraints)
    if (
        view.registry_authority != authorities[REGISTRY_AUTHORITY]
        or view.receipt_authority != authorities[RECEIPT_AUTHORITY]
        or view.reconciliation_authority != authorities[RECONCILIATION_AUTHORITY]
    ):
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    if view.verification_domain == PRODUCTION and (principal != authorities[REGISTRY_AUTHORITY] or envelope.get("issuer_role") != REGISTRY_AUTHORITY):
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")
    if view.verification_domain == FIXTURE_ONLY and envelope.get("issuer_role") in {REGISTRY_AUTHORITY, RECEIPT_AUTHORITY, RECONCILIATION_AUTHORITY}:
        raise AdjunctRegistryFailure("REGISTRY_VERIFIED_INVALID")


def verify_adjunct_trust_registry(envelope: VerifiedEnvelope, schemas: AdjunctSchemaStore, required_verification_domain: Literal["FIXTURE_ONLY", "PRODUCTION"], now_epoch_seconds: int) -> VerifiedAdjunctTrustRegistry:
    if type(schemas) is not AdjunctSchemaStore or required_verification_domain not in {FIXTURE_ONLY, PRODUCTION}:
        raise TypeError("registry verification requires a schema store and closed domain")
    try:
        principal = principal_binding(envelope)
        payload = loads_canonical(envelope.payload_canonical_bytes)
        schemas.validate(REGISTRY_SCHEMA_ID, envelope.payload_schema_sha256, payload)
    except (EnvelopeFailure, TypeError, ValueError) as error:
        raise AdjunctRegistryFailure("REGISTRY_ENVELOPE_INVALID") from error
    if envelope.verification_domain != required_verification_domain or type(payload) is not dict or envelope.payload_schema_id != REGISTRY_SCHEMA_ID:
        raise AdjunctRegistryFailure("REGISTRY_DOMAIN_MISMATCH")
    digests, constraints = _schema_digests(payload), _constraints(payload)
    if digests != tuple(item for item in schemas.schema_digests() if item[0] != REGISTRY_SCHEMA_ID):
        raise AdjunctRegistryFailure("REGISTRY_SCHEMA_SET_INVALID")
    authorities = dict(constraints)
    if required_verification_domain == PRODUCTION and (envelope.issuer_role != REGISTRY_AUTHORITY or principal != authorities[REGISTRY_AUTHORITY]):
        raise AdjunctRegistryFailure("REGISTRY_PRINCIPAL_MISMATCH")
    if required_verification_domain == FIXTURE_ONLY and envelope.issuer_role in {REGISTRY_AUTHORITY, RECEIPT_AUTHORITY, RECONCILIATION_AUTHORITY}:
        raise AdjunctRegistryFailure("REGISTRY_FIXTURE_AUTHORITY_FORBIDDEN")
    outer = loads_canonical(envelope.envelope_canonical_bytes)
    if type(outer) is not dict or payload.get("issued_at") != outer.get("issued_at") or payload.get("expires_at") != outer.get("expires_at") or payload.get("revocation_epoch") != envelope.trust.issuer_revocation_epoch:
        raise AdjunctRegistryFailure("REGISTRY_PAYLOAD_INVALID")
    view = VerifiedAdjunctTrustRegistry(_TOKEN, envelope_sha256=envelope.envelope_sha256, payload_sha256=envelope.payload_sha256, envelope_canonical_bytes=envelope.envelope_canonical_bytes, payload_canonical_bytes=envelope.payload_canonical_bytes, verification_domain=envelope.verification_domain, trust=envelope.trust, issued_at_epoch_seconds=envelope.issued_at_epoch_seconds, expires_at_epoch_seconds=envelope.expires_at_epoch_seconds, revocation_epoch=payload["revocation_epoch"], adjunct_schema_digests=digests, role_principal_constraints=constraints, registry_authority=authorities[REGISTRY_AUTHORITY], receipt_authority=authorities[RECEIPT_AUTHORITY], reconciliation_authority=authorities[RECONCILIATION_AUTHORITY])
    _remember(view, envelope.envelope_canonical_bytes, envelope.payload_canonical_bytes, envelope.trust, _fingerprint(view))
    VerifiedAdjunctTrustRegistry.require_verified(view, now_epoch_seconds)
    return view
