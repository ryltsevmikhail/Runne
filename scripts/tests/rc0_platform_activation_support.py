"""Fixture-only construction and floor authentication for activation tests."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, PrincipalBinding, TrustVerification, VerifiedEnvelope, verify_signed_envelope
from scripts.rc0_policy.platform_policy import fixture_verify_mapping_policy
from scripts.rc0_policy.activation import VerifiedFloorWitness, _fixture_floor_digest, _seal_fixture_floor
from scripts.tests.rc0_platform_envelope_support import _NOW, _fixture_envelope, _fixture_schema_store, _schema_digest, _sign, fixture_sign, valid_fixture_envelope
from scripts.tests.rc0_platform_policy_support import _envelope, _principals, valid_mapping_fixture


_ACTIVATION_ID = "018f0000-0000-7000-8000-000000000000"
_HEX = re.compile(r"[0-9a-f]{64}")
_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class ActivationFixture:
    intent: VerifiedEnvelope
    runner_receipt: VerifiedEnvelope
    downstream_receipt: VerifiedEnvelope
    snapshot: VerifiedEnvelope
    mapping: object
    adjunct_trust: object
    floor: VerifiedFloorWitness
    runner_subject_id: str
    downstream_subject_id: str
    expected_consumer_verifier_build_sha256s: dict[str, str]
    now_epoch_seconds: int = _NOW


def _principal(role: str, subject: str) -> dict[str, str]:
    return {
        "subject_id": subject,
        "controlling_account_id": role + "-account",
        "delegated_session_id": role + "-session",
        "lane_id": role + "-lane",
    }


def timed_envelope(payload: object, schema_id: str, role: str, principal: dict[str, str], issued_at: str, now: int) -> VerifiedEnvelope:
    _, verifier = valid_fixture_envelope()
    outer = _fixture_envelope(payload)
    outer.update(payload_schema_id=schema_id, payload_schema_sha256=_schema_digest(schema_id), payload_sha256=hashlib.sha256(canonical_bytes(payload)).hexdigest(), issuer_role=role, issuer_subject_id=principal["subject_id"], issuer_controlling_account_id=principal["controlling_account_id"], issuer_delegated_session_id=principal["delegated_session_id"], issuer_lane_id=principal["lane_id"], issued_at=issued_at)
    return verify_signed_envelope(_sign(outer), _fixture_schema_store(), verifier, now)


def alternate_activation_schema_envelope(value: VerifiedEnvelope, now: int) -> VerifiedEnvelope:
    payload = loads_canonical(value.payload_canonical_bytes); payload["untrusted_extra"] = "fixture"
    schema_id = value.payload_schema_id
    filenames = {
        "gocode.rc0.policy-activation-intent/1": "rc0-policy-activation-intent-v1.schema.json",
        "gocode.rc0.policy-acceptance-receipt/1": "rc0-policy-acceptance-receipt-v1.schema.json",
        "gocode.rc0.policy-activation-snapshot/1": "rc0-policy-activation-snapshot-v1.schema.json",
    }
    schema = json.loads((_ROOT / "docs/schemas" / filenames[schema_id]).read_text())
    schema["properties"]["untrusted_extra"] = {"type": "string"}
    documents = dict(_fixture_schema_store()._schemas); documents[schema_id] = canonical_bytes(schema)
    outer = _fixture_envelope(payload); outer.update(payload_schema_id=schema_id, payload_schema_sha256=hashlib.sha256(documents[schema_id]).hexdigest(), payload_sha256=hashlib.sha256(canonical_bytes(payload)).hexdigest(), issuer_role=value.issuer_role, issuer_subject_id=value.issuer_subject_id, issuer_controlling_account_id=value.issuer_controlling_account_id, issuer_delegated_session_id=value.issuer_delegated_session_id, issuer_lane_id=value.issuer_lane_id)
    _, verifier = valid_fixture_envelope()
    return verify_signed_envelope(_sign(outer), AdjunctSchemaStore(documents), verifier, now)


def alternate_intent_schema_envelope(value: VerifiedEnvelope, now: int) -> VerifiedEnvelope:
    return alternate_activation_schema_envelope(value, now)


def reframed_envelope(value: VerifiedEnvelope, now: int, **changes: object) -> VerifiedEnvelope:
    outer = loads_canonical(value.envelope_canonical_bytes); outer.update(changes)
    def verifier(transcript: bytes, signature: str, _profile: str) -> TrustVerification | None:
        end = 4 + len(b"gocode.external-signed-envelope/1"); size = int.from_bytes(transcript[end:end + 8], "big")
        signed = loads_canonical(transcript[end + 8:])
        if len(transcript[end + 8:]) != size or type(signed) is not dict or fixture_sign(signed) != signature: return None
        principal = PrincipalBinding(signed["issuer_role"], signed["issuer_subject_id"], signed["issuer_controlling_account_id"], signed["issuer_delegated_session_id"], signed["issuer_lane_id"])
        domain = "FIXTURE_ONLY" if signed["issuer"] == "FIXTURE_ONLY" else "PRODUCTION"
        return TrustVerification(domain, hashlib.sha256(transcript).hexdigest(), signed["issuer"], signed["issuer_key_id"], signed["issuer_key_epoch"], signed["issuer_revocation_epoch"], signed["signature_profile_id"], principal)
    return verify_signed_envelope(_sign(outer), _fixture_schema_store(), verifier, now)


def _floor_bytes(value: dict[str, object], protected_digest: str) -> bytes:
    if not _floor_projection(value) or type(protected_digest) is not str or _HEX.fullmatch(protected_digest) is None:
        raise ValueError("FLOOR_FIXTURE_INVALID")
    return canonical_bytes({**value, "protected_digest": protected_digest})


def floor_digest(value: dict[str, object]) -> str:
    return _fixture_floor_digest(value)


def _floor_projection(value: object) -> bool:
    if type(value) is not dict or set(value) != {"repository_id", "generation", "state", "activation_epoch", "snapshot_envelope_sha256", "predecessor_snapshot_envelope_sha256"}:
        return False
    if value["repository_id"] != "gocode" or type(value["generation"]) is not int or type(value["activation_epoch"]) is not int or value["state"] not in {"genesis", "current"}:
        return False
    for key in ("snapshot_envelope_sha256", "predecessor_snapshot_envelope_sha256"):
        if value[key] is not None and (type(value[key]) is not str or _HEX.fullmatch(value[key]) is None): return False
    if value["state"] == "genesis": return (value["generation"], value["activation_epoch"], value["snapshot_envelope_sha256"], value["predecessor_snapshot_envelope_sha256"]) == (0, 0, None, None)
    return value["generation"] > 0 and value["activation_epoch"] > 0 and value["snapshot_envelope_sha256"] is not None and (value["activation_epoch"] == 1) == (value["predecessor_snapshot_envelope_sha256"] is None) and value["snapshot_envelope_sha256"] != value["predecessor_snapshot_envelope_sha256"]


def verify_fixture_floor(raw: bytes | None, protected_digest: str) -> VerifiedFloorWitness:
    if type(raw) is not bytes or type(protected_digest) is not str:
        raise ValueError("FLOOR_FIXTURE_INVALID")
    try:
        parsed = loads_canonical(raw)
    except Exception as error:
        raise ValueError("FLOOR_FIXTURE_INVALID") from error
    fields = {
        "repository_id", "generation", "state", "activation_epoch",
        "snapshot_envelope_sha256", "predecessor_snapshot_envelope_sha256",
        "protected_digest",
    }
    if type(parsed) is not dict or set(parsed) != fields or canonical_bytes(parsed) != raw:
        raise ValueError("FLOOR_FIXTURE_INVALID")
    projection = {key: parsed[key] for key in fields - {"protected_digest"}}
    if (
        parsed["protected_digest"] != protected_digest
        or protected_digest != _fixture_floor_digest(projection)
    ):
        raise ValueError("FLOOR_FIXTURE_INVALID")
    if not _floor_projection(projection):
        raise ValueError("FLOOR_FIXTURE_INVALID")
    return _seal_fixture_floor(projection, protected_digest)


def valid_active_fixture() -> ActivationFixture:
    mapping_input = valid_mapping_fixture()
    mapping = fixture_verify_mapping_policy(**mapping_input.arguments())
    registry = mapping_input.adjunct_trust
    policy = _principals()["policy_authority"]
    runner, downstream = _principal("runner", "fixture-runner-subject"), _principal("downstream", "fixture-downstream-subject")
    base = {
        "repository_id": "gocode", "activation_id": _ACTIVATION_ID,
        "mapping_policy_envelope_sha256": mapping.envelope_sha256,
        "adjunct_trust_registry_envelope_sha256": registry.envelope_sha256,
        "adjunct_trust_registry_payload_sha256": registry.payload_sha256,
        "rc0_qualification_policy_digest": mapping.rc0_qualification_policy_digest,
        "shared_decision_payload_sha256": mapping.shared_decision_payload_sha256,
        "activation_epoch": 1, "predecessor_activation_snapshot_envelope_sha256": None,
    }
    intent_payload = {
        **base, "schema_version": "gocode.rc0.policy-activation-intent/1",
        "activation_action": "activate", "signature_key_epoch": 7, "revocation_epoch": 3,
        "runner_consumer_subject_id": runner["subject_id"], "downstream_consumer_subject_id": downstream["subject_id"],
        "not_before": "2023-11-14T22:13:10Z", "activation_deadline": "2023-11-14T22:13:30Z",
    }
    intent = _envelope(intent_payload, "gocode.rc0.policy-activation-intent/1", "policy_authority", policy)
    builds = {"runner": "1" * 64, "downstream": "2" * 64}
    def receipt(role: str, principal: dict[str, str]) -> VerifiedEnvelope:
        payload = {
            "schema_version": "gocode.rc0.policy-acceptance-receipt/1", "repository_id": "gocode",
            "activation_intent_envelope_sha256": intent.envelope_sha256, "consumer_role": role,
            "consumer_subject_id": principal["subject_id"], "accepted_mapping_policy_envelope_sha256": mapping.envelope_sha256,
            "accepted_adjunct_trust_registry_envelope_sha256": registry.envelope_sha256,
            "accepted_adjunct_trust_registry_payload_sha256": registry.payload_sha256,
            "accepted_rc0_qualification_policy_digest": mapping.rc0_qualification_policy_digest,
            "accepted_at": "2023-11-14T22:13:20Z", "consumer_verifier_build_sha256": builds[role],
        }
        return _envelope(payload, "gocode.rc0.policy-acceptance-receipt/1", role, principal)
    runner_receipt, downstream_receipt = receipt("runner", runner), receipt("downstream", downstream)
    snapshot_base = {key: value for key, value in base.items() if key != "shared_decision_payload_sha256"}
    snapshot = _envelope({
        **snapshot_base, "schema_version": "gocode.rc0.policy-activation-snapshot/1",
        "activation_intent_envelope_sha256": intent.envelope_sha256,
        "runner_acceptance_receipt_envelope_sha256": runner_receipt.envelope_sha256,
        "downstream_acceptance_receipt_envelope_sha256": downstream_receipt.envelope_sha256,
        "state": "active", "activated_at": "2023-11-14T22:13:20Z",
    }, "gocode.rc0.policy-activation-snapshot/1", "policy_authority", policy)
    floor_projection = {
        "repository_id": "gocode", "generation": 0, "state": "genesis", "activation_epoch": 0,
        "snapshot_envelope_sha256": None, "predecessor_snapshot_envelope_sha256": None,
    }
    floor_digest = _fixture_floor_digest(floor_projection)
    floor = verify_fixture_floor(_floor_bytes(floor_projection, floor_digest), floor_digest)
    return ActivationFixture(intent, runner_receipt, downstream_receipt, snapshot, mapping, registry, floor, runner["subject_id"], downstream["subject_id"], builds)


def replace_receipt_intent(value: VerifiedEnvelope, digest: str) -> VerifiedEnvelope:
    payload = loads_canonical(value.payload_canonical_bytes)
    payload["activation_intent_envelope_sha256"] = digest
    principal = {
        "subject_id": value.issuer_subject_id,
        "controlling_account_id": value.issuer_controlling_account_id,
        "delegated_session_id": value.issuer_delegated_session_id,
        "lane_id": value.issuer_lane_id,
    }
    return _envelope(payload, "gocode.rc0.policy-acceptance-receipt/1", value.issuer_role, principal)
