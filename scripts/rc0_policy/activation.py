"""Pure fixture-only verification of the signed activation graph."""

from __future__ import annotations

import hashlib
import re
import weakref
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Mapping, Sequence

from scripts.rc0_policy.adjunct_registry import VerifiedAdjunctTrustRegistry
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import EnvelopeFailure, PrincipalBinding, VerifiedEnvelope, require_fixture_verified
from scripts.rc0_policy.platform_policy_mapping import VerifiedMappingPolicy


ROOT = Path(__file__).resolve().parents[2]
_VIEW_TOKEN = object()
_HEX = re.compile(r"[0-9a-f]{64}")
_UUID7 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{6}))?Z")
_SCHEMAS = {"intent": ("gocode.rc0.policy-activation-intent/1", "rc0-policy-activation-intent-v1.schema.json"), "receipt": ("gocode.rc0.policy-acceptance-receipt/1", "rc0-policy-acceptance-receipt-v1.schema.json"), "snapshot": ("gocode.rc0.policy-activation-snapshot/1", "rc0-policy-activation-snapshot-v1.schema.json")}
_FLOOR_DOMAIN = b"gocode.rc0.fixture-floor-projection/1\0"


class ActivationFailure(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, init=False)
class VerifiedFloorWitness:
    verification_domain: Literal["FIXTURE_ONLY"]
    repository_id: str
    generation: int
    state: Literal["genesis", "current"]
    activation_epoch: int
    snapshot_envelope_sha256: str | None
    predecessor_snapshot_envelope_sha256: str | None
    _verification_token: object = field(repr=False, compare=False)

    def __init__(self, token: object, /, **fields: object) -> None:
        if not _floor_owned(token) or set(fields) != set(self.__dataclass_fields__) - {"_verification_token"}: raise TypeError("VerifiedFloorWitness is sealer-owned")
        for name, value in fields.items(): object.__setattr__(self, name, value)
        object.__setattr__(self, "_verification_token", token)


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class ActivationView:
    activation_id: str; activation_epoch: int; mapping_policy_envelope_sha256: str
    adjunct_trust_registry_envelope_sha256: str; adjunct_trust_registry_payload_sha256: str
    rc0_qualification_policy_digest: str; snapshot_envelope_sha256: str
    policy_authority_identity: PrincipalBinding; runner_consumer_identity: PrincipalBinding | None
    downstream_consumer_identity: PrincipalBinding | None; state: Literal["active", "revoked"]
    _canonical_source_bytes: bytes; _verification_token: object = field(repr=False, compare=False)

    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _VIEW_TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_verification_token"}: raise TypeError("ActivationView is verifier-owned")
        for name, value in fields.items(): object.__setattr__(self, name, value)
        object.__setattr__(self, "_verification_token", token)

    def require_verified(self, now_epoch_seconds: int) -> None:
        state = _VIEWS.get(self)
        if type(self) is not ActivationView or getattr(self, "_verification_token", None) is not _VIEW_TOKEN or state is None: _fail("ACTIVATION_VERIFIED_INVALID")
        try: fields, source = _verify(*state.inputs, now_epoch_seconds); expected, actual = _view_fingerprint(fields), _view_fingerprint(_public(self))
        except ActivationFailure as error: raise ActivationFailure("ACTIVATION_VERIFIED_INVALID") from error
        if actual != expected or actual != state.public_fingerprint or type(self._canonical_source_bytes) is not bytes or self._canonical_source_bytes != source or state.fingerprint != source: _fail("ACTIVATION_VERIFIED_INVALID")

    def require_dependencies(self, mapping: VerifiedMappingPolicy, adjunct_trust: VerifiedAdjunctTrustRegistry, now_epoch_seconds: int) -> None:
        self.require_verified(now_epoch_seconds)
        state = _VIEWS.get(self)
        if type(mapping) is not VerifiedMappingPolicy or type(adjunct_trust) is not VerifiedAdjunctTrustRegistry or state is None or mapping is not state.inputs[3] or adjunct_trust is not state.inputs[4]: _fail("ACTIVATION_DEPENDENCY_INVALID")


@dataclass(frozen=True)
class _ViewState: inputs: tuple[object, ...]; fingerprint: bytes; public_fingerprint: str
_VIEWS: weakref.WeakKeyDictionary[ActivationView, _ViewState] = weakref.WeakKeyDictionary()


def _fail(code: str) -> None: raise ActivationFailure(code)
def _sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()
def _time(value: object) -> int:
    if type(value) is not str or (match := _TIME.fullmatch(value)) is None: _fail("TIME_INVALID")
    try: parsed = datetime(*map(int, match.groups()[:6]))
    except ValueError as error: raise ActivationFailure("TIME_INVALID") from error
    return ((parsed.date() - date(1970, 1, 1)).days * 86400 + parsed.hour * 3600 + parsed.minute * 60 + parsed.second) * 1_000_000 + int(match.group(7) or "0")
def _principal(value: VerifiedEnvelope) -> PrincipalBinding:
    return PrincipalBinding(value.issuer_role, value.issuer_subject_id, value.issuer_controlling_account_id, value.issuer_delegated_session_id, value.issuer_lane_id)
def _authority(value: VerifiedEnvelope) -> tuple[object, ...]:
    return (_principal(value), value.issuer, value.issuer_key_id, value.issuer_key_epoch, value.issuer_revocation_epoch, value.signature_profile_id)
def _floor_fields(value: VerifiedFloorWitness) -> tuple[object, ...]:
    return (value.verification_domain, value.repository_id, value.generation, value.state, value.activation_epoch, value.snapshot_envelope_sha256, value.predecessor_snapshot_envelope_sha256)
def _public(value: ActivationView) -> tuple[object, ...]:
    return (value.activation_id, value.activation_epoch, value.mapping_policy_envelope_sha256, value.adjunct_trust_registry_envelope_sha256, value.adjunct_trust_registry_payload_sha256, value.rc0_qualification_policy_digest, value.snapshot_envelope_sha256, value.policy_authority_identity, value.runner_consumer_identity, value.downstream_consumer_identity, value.state)
def _principal_fields(value: object, required: bool) -> list[str] | None:
    if value is None and not required: return None
    if type(value) is not PrincipalBinding or any(type(item) is not str for item in (value.role_id, value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id)): _fail("ACTIVATION_VERIFIED_INVALID")
    return [value.role_id, value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id]
def _view_fingerprint(fields: object) -> str:
    if type(fields) is not tuple or len(fields) != 11: _fail("ACTIVATION_VERIFIED_INVALID")
    activation_id, epoch, mapping, registry_envelope, registry_payload, policy, snapshot, authority, runner, downstream, state = fields
    if any(type(item) is not str for item in (activation_id, mapping, registry_envelope, registry_payload, policy, snapshot)) or type(epoch) is not int or type(state) is not str or state not in {"active", "revoked"}: _fail("ACTIVATION_VERIFIED_INVALID")
    return _sha(canonical_bytes({"activation": [activation_id, epoch, state], "mapping": mapping, "registry": [registry_envelope, registry_payload], "policy": policy, "snapshot": snapshot, "authorities": [_principal_fields(authority, True), _principal_fields(runner, False), _principal_fields(downstream, False)]}))
def _schema_digests() -> dict[str, str]:
    return {identity: _sha((ROOT / "docs/schemas" / filename).read_bytes()) for identity, filename in _SCHEMAS.values()}


def _floor_projection(value: Mapping[str, object]) -> tuple[object, ...]:
    keys = {"repository_id", "generation", "state", "activation_epoch", "snapshot_envelope_sha256", "predecessor_snapshot_envelope_sha256"}
    if type(value) is not dict or set(value) != keys or value.get("repository_id") != "gocode" or type(value.get("generation")) is not int or type(value.get("activation_epoch")) is not int or value.get("state") not in {"genesis", "current"}: _fail("FLOOR_INVALID")
    for key in ("snapshot_envelope_sha256", "predecessor_snapshot_envelope_sha256"):
        if value[key] is not None and (type(value[key]) is not str or _HEX.fullmatch(value[key]) is None): _fail("FLOOR_INVALID")
    fields = ("FIXTURE_ONLY", *(value[key] for key in ("repository_id", "generation", "state", "activation_epoch", "snapshot_envelope_sha256", "predecessor_snapshot_envelope_sha256")))
    if value["state"] == "genesis" and fields[2:] != (0, "genesis", 0, None, None): _fail("FLOOR_INVALID")
    if value["state"] == "current" and (value["generation"] <= 0 or value["activation_epoch"] <= 0 or value["snapshot_envelope_sha256"] is None or (value["activation_epoch"] == 1) != (value["predecessor_snapshot_envelope_sha256"] is None) or value["predecessor_snapshot_envelope_sha256"] == value["snapshot_envelope_sha256"]): _fail("FLOOR_INVALID")
    return fields
def _fixture_floor_digest(projection: Mapping[str, object]) -> str:
    _floor_projection(projection)
    return _sha(_FLOOR_DOMAIN + canonical_bytes(dict(projection)))


def _fixture_floor_authority():
    token, records = object(), {}
    def owned(value: object) -> bool: return value is token
    def forget(identity: int) -> None: records.pop(identity, None)
    def seal(projection: Mapping[str, object], protected_digest: str) -> VerifiedFloorWitness:
        fields = _floor_projection(projection)
        if type(protected_digest) is not str or protected_digest != _fixture_floor_digest(projection): _fail("FLOOR_INVALID")
        witness = VerifiedFloorWitness(token, verification_domain=fields[0], repository_id=fields[1], generation=fields[2], state=fields[3], activation_epoch=fields[4], snapshot_envelope_sha256=fields[5], predecessor_snapshot_envelope_sha256=fields[6])
        identity = id(witness); records[identity] = (weakref.ref(witness, lambda _: forget(identity)), fields, protected_digest)
        return witness
    def record(value: VerifiedFloorWitness) -> tuple[tuple[object, ...], str] | None:
        entry = records.get(id(value)); return None if entry is None or entry[0]() is not value else (entry[1], entry[2])
    return owned, seal, record


_floor_owned, _seal_fixture_floor, _floor_record = _fixture_floor_authority()


def _payload(value: VerifiedEnvelope, kind: str, registry: Mapping[str, str], now: int) -> dict[str, object]:
    identity = _SCHEMAS[kind][0]
    try: require_fixture_verified(value); payload = loads_canonical(value.payload_canonical_bytes)
    except (EnvelopeFailure, TypeError, ValueError) as error: raise ActivationFailure("ENVELOPE_INVALID") from error
    if type(payload) is not dict or value.payload_schema_id != identity or registry.get(identity) != _schema_digests()[identity] or value.payload_schema_sha256 != registry[identity] or not _time(value.not_before) <= _time(value.issued_at) <= now * 1_000_000 <= _time(value.expires_at): _fail("ENVELOPE_INVALID")
    return payload
def _floor(value: VerifiedFloorWitness, epoch: int, predecessor: object, candidate: str) -> None:
    record = _floor_record(value)
    if type(value) is not VerifiedFloorWitness or not _floor_owned(getattr(value, "_verification_token", None)) or record is None or record[0] != _floor_fields(value): _fail("FLOOR_INVALID")
    if value.state == "genesis":
        if predecessor is not None or epoch != 1: _fail("FLOOR_GENESIS_MISMATCH")
        return
    if value.state != "current" or value.generation <= 0 or value.activation_epoch <= 0 or type(value.snapshot_envelope_sha256) is not str or _HEX.fullmatch(value.snapshot_envelope_sha256) is None: _fail("FLOOR_INVALID")
    if (value.activation_epoch == 1) != (value.predecessor_snapshot_envelope_sha256 is None) or (value.predecessor_snapshot_envelope_sha256 is not None and (value.predecessor_snapshot_envelope_sha256 == value.snapshot_envelope_sha256 or _HEX.fullmatch(value.predecessor_snapshot_envelope_sha256) is None)): _fail("FLOOR_INVALID")
    if predecessor != value.snapshot_envelope_sha256 or epoch != value.activation_epoch + 1 or candidate in {value.snapshot_envelope_sha256, value.predecessor_snapshot_envelope_sha256}: _fail("FLOOR_LINEAGE_MISMATCH")


def _source(intent: VerifiedEnvelope, receipts: Sequence[VerifiedEnvelope], snapshot: VerifiedEnvelope, mapping: VerifiedMappingPolicy, registry: VerifiedAdjunctTrustRegistry, floor: VerifiedFloorWitness, runner: str, downstream: str, builds: Mapping[str, str]) -> bytes:
    try:
        record = _floor_record(floor)
        if record is None: _fail("FLOOR_INVALID")
        return canonical_bytes({"intent": loads_canonical(intent.envelope_canonical_bytes), "receipts": [loads_canonical(item.envelope_canonical_bytes) for item in receipts], "snapshot": loads_canonical(snapshot.envelope_canonical_bytes), "mapping": loads_canonical(mapping._canonical_source_bytes), "registry": loads_canonical(registry.envelope_canonical_bytes), "floor": {"fields": list(record[0]), "protected_digest": record[1]}, "consumers": {"runner": runner, "downstream": downstream, "builds": dict(builds)}})
    except Exception as error: raise ActivationFailure("ACTIVATION_VERIFIED_INVALID") from error
def _distinct(*values: PrincipalBinding) -> None:
    parts = [part for value in values for part in (value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id)]
    if len(set(parts)) != len(parts): _fail("PRINCIPAL_OVERLAP")


def _verify(intent: VerifiedEnvelope, receipts: Sequence[VerifiedEnvelope], snapshot: VerifiedEnvelope, mapping: VerifiedMappingPolicy, registry: VerifiedAdjunctTrustRegistry, floor: VerifiedFloorWitness, runner: str, downstream: str, builds: Mapping[str, str], now: int) -> tuple[tuple[object, ...], bytes]:
    if type(now) is not int or isinstance(now, bool) or any(type(item) is not str or not item for item in (runner, downstream)) or runner == downstream or set(builds) != {"runner", "downstream"} or any(type(item) is not str or _HEX.fullmatch(item) is None for item in builds.values()): _fail("ACTIVATION_INPUT_INVALID")
    if type(mapping) is not VerifiedMappingPolicy or type(registry) is not VerifiedAdjunctTrustRegistry: _fail("MAPPING_OR_REGISTRY_INVALID")
    if mapping.adjunct_trust is not registry: _fail("MAPPING_OR_REGISTRY_INVALID")
    try: VerifiedMappingPolicy.require_verified(mapping, now); VerifiedAdjunctTrustRegistry.require_verified(registry, now)
    except Exception as error: raise ActivationFailure("MAPPING_OR_REGISTRY_INVALID") from error
    if mapping.adjunct_trust_registry_envelope_sha256 != registry.envelope_sha256 or mapping.adjunct_trust_registry_payload_sha256 != registry.payload_sha256 or mapping.adjunct_schema_digests != registry.adjunct_schema_digests: _fail("MAPPING_OR_REGISTRY_INVALID")
    schemas = dict(registry.adjunct_schema_digests); intent_payload, snapshot_payload = _payload(intent, "intent", schemas, now), _payload(snapshot, "snapshot", schemas, now)
    policy = dict(registry.role_principal_constraints).get("policy_authority")
    if policy is None or _authority(intent) != _authority(snapshot) or _principal(intent) != policy: _fail("POLICY_AUTHORITY_MISMATCH")
    base = {"repository_id": "gocode", "mapping_policy_envelope_sha256": mapping.envelope_sha256, "adjunct_trust_registry_envelope_sha256": registry.envelope_sha256, "adjunct_trust_registry_payload_sha256": registry.payload_sha256, "rc0_qualification_policy_digest": mapping.rc0_qualification_policy_digest}
    if any(intent_payload.get(key) != value or snapshot_payload.get(key) != value for key, value in base.items()) or intent_payload.get("shared_decision_payload_sha256") != mapping.shared_decision_payload_sha256 or intent_payload.get("not_before") != intent.not_before or intent_payload.get("signature_key_epoch") != intent.issuer_key_epoch or intent_payload.get("revocation_epoch") != intent.issuer_revocation_epoch or intent_payload.get("activation_epoch") != mapping.activation_epoch or type(intent_payload.get("activation_id")) is not str or _UUID7.fullmatch(intent_payload["activation_id"]) is None: _fail("INTENT_INVALID")
    issued, deadline, activated = _time(intent.issued_at), _time(intent_payload.get("activation_deadline")), _time(snapshot_payload.get("activated_at"))
    if not issued <= now * 1_000_000 <= deadline <= _time(intent.expires_at) or snapshot_payload.get("activated_at") != snapshot.issued_at or not issued <= activated <= deadline: _fail("INTENT_TIME_INVALID")
    keys = ("activation_id", "activation_epoch", "predecessor_activation_snapshot_envelope_sha256")
    if any(snapshot_payload.get(key) != intent_payload.get(key) for key in keys) or snapshot_payload.get("activation_intent_envelope_sha256") != intent.envelope_sha256: _fail("SNAPSHOT_LINEAGE_MISMATCH")
    epoch, predecessor = intent_payload["activation_epoch"], intent_payload["predecessor_activation_snapshot_envelope_sha256"]
    if type(epoch) is not int or isinstance(epoch, bool): _fail("INTENT_INVALID")
    _floor(floor, epoch, predecessor, snapshot.envelope_sha256); subjects = {"runner": runner, "downstream": downstream}
    if intent_payload.get("runner_consumer_subject_id") != runner or intent_payload.get("downstream_consumer_subject_id") != downstream: _fail("CONSUMER_SUBJECT_MISMATCH")
    prefix = (intent_payload["activation_id"], epoch, mapping.envelope_sha256, registry.envelope_sha256, registry.payload_sha256, mapping.rc0_qualification_policy_digest, snapshot.envelope_sha256, policy)
    if intent_payload.get("activation_action") == "revoke" or snapshot_payload.get("state") == "revoked":
        if intent_payload.get("activation_action") != "revoke" or snapshot_payload.get("state") != "revoked" or receipts or snapshot_payload.get("runner_acceptance_receipt_envelope_sha256") is not None or snapshot_payload.get("downstream_acceptance_receipt_envelope_sha256") is not None: _fail("REVOKE_MISMATCH")
        return (*prefix, None, None, "revoked"), _source(intent, receipts, snapshot, mapping, registry, floor, runner, downstream, builds)
    found: dict[str, PrincipalBinding] = {}
    if intent_payload.get("activation_action") != "activate" or snapshot_payload.get("state") != "active" or len(receipts) != 2: _fail("RECEIPT_SET_MISMATCH")
    for receipt in receipts:
        payload = _payload(receipt, "receipt", schemas, now); role = payload.get("consumer_role")
        if role not in subjects or role in found or receipt.issuer_role != role or payload.get("consumer_subject_id") != subjects[role] or receipt.issuer_subject_id != subjects[role] or payload.get("activation_intent_envelope_sha256") != intent.envelope_sha256: _fail("RECEIPT_INTENT_MISMATCH")
        if payload.get("accepted_mapping_policy_envelope_sha256") != mapping.envelope_sha256 or payload.get("accepted_adjunct_trust_registry_envelope_sha256") != registry.envelope_sha256 or payload.get("accepted_adjunct_trust_registry_payload_sha256") != registry.payload_sha256 or payload.get("accepted_rc0_qualification_policy_digest") != mapping.rc0_qualification_policy_digest or payload.get("consumer_verifier_build_sha256") != builds[role]: _fail("RECEIPT_LINEAGE_MISMATCH")
        if payload.get("accepted_at") != receipt.issued_at or not issued <= _time(payload["accepted_at"]) <= activated: _fail("RECEIPT_TIME_INVALID")
        found[role] = _principal(receipt)
    if set(found) != set(subjects) or snapshot_payload.get("runner_acceptance_receipt_envelope_sha256") != next(item.envelope_sha256 for item in receipts if item.issuer_role == "runner") or snapshot_payload.get("downstream_acceptance_receipt_envelope_sha256") != next(item.envelope_sha256 for item in receipts if item.issuer_role == "downstream"): _fail("RECEIPT_SET_MISMATCH")
    _distinct(*dict(registry.role_principal_constraints).values(), *found.values())
    return (*prefix, found["runner"], found["downstream"], "active"), _source(intent, receipts, snapshot, mapping, registry, floor, runner, downstream, builds)


def fixture_verify_activation(intent: VerifiedEnvelope, receipts: Sequence[VerifiedEnvelope], snapshot: VerifiedEnvelope, mapping: VerifiedMappingPolicy, adjunct_trust: VerifiedAdjunctTrustRegistry, floor: VerifiedFloorWitness, runner_subject_id: str, downstream_subject_id: str, expected_consumer_verifier_build_sha256s: Mapping[str, str], now_epoch_seconds: int) -> ActivationView:
    try:
        if not isinstance(receipts, Sequence) or isinstance(receipts, (str, bytes)) or not isinstance(expected_consumer_verifier_build_sha256s, Mapping): _fail("ACTIVATION_INPUT_INVALID")
        frozen_receipts = tuple(sorted(tuple(receipts), key=lambda item: item.envelope_sha256)); frozen_builds = MappingProxyType(dict(expected_consumer_verifier_build_sha256s))
    except ActivationFailure: raise
    except Exception as error: raise ActivationFailure("ACTIVATION_INPUT_INVALID") from error
    inputs = (intent, frozen_receipts, snapshot, mapping, adjunct_trust, floor, runner_subject_id, downstream_subject_id, frozen_builds)
    fields, source = _verify(*inputs, now_epoch_seconds); names = [name for name in ActivationView.__dataclass_fields__ if name not in {"_canonical_source_bytes", "_verification_token"}]
    view = ActivationView(_VIEW_TOKEN, **dict(zip(names, fields)), _canonical_source_bytes=source); _VIEWS[view] = _ViewState(inputs, source, _view_fingerprint(fields)); ActivationView.require_verified(view, now_epoch_seconds)
    return view


def verify_activation(*args: object, **kwargs: object) -> None:
    """Reject the superseded G1 production activation entrypoint before parsing."""
    _fail("SUPERSEDED_G1_UNSUPPORTED")
