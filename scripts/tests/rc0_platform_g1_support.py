"""Fixture-only builders for the G1-shaped owner-authority receipt tests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import (
    AdjunctSchemaStore, FIXTURE_ONLY, PrincipalBinding, SignatureVerifier,
    TrustVerification, VerifiedEnvelope, signature_transcript,
    timestamp_epoch_seconds, verify_signed_envelope,
)
from scripts.rc0_policy.adjunct_registry import (
    VerifiedAdjunctTrustRegistry, verify_adjunct_trust_registry,
)


NOW = 1_700_000_000
ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / ".superpowers/sdd/2026-08-09-v1-platform-scope-local-contracts/g1-ceremony"
G1_ROLES = (
    "POST_RC0_ADJUNCT_REGISTRY_AUTHORITY", "POST_RC0_G1_RECEIPT_AUTHORITY",
    "POST_RC0_RECONCILIATION_AUTHORITY", "runtime_platform_owner",
    "desktop_platform_owner", "mapping_policy_authority",
    "rc0_qualification_reporter", "rc0_qualification_declarer",
    "artifact_classifier_a", "artifact_classifier_b",
    "native_host_attestor", "external_canary_operator",
    "qualification_aggregator", "policy_authority",
)
SIGNER_ROLES = ("POST_RC0_ADJUNCT_REGISTRY_AUTHORITY", "POST_RC0_G1_RECEIPT_AUTHORITY",
                "runtime_platform_owner", "desktop_platform_owner")
SCHEMAS = (
    ("gocode.external-signed-envelope/1", "rc0-external-signed-envelope-v1.schema.json"),
    ("gocode.governance.platform-decision-acceptance/1", "platform-decision-acceptance-v1.schema.json"),
    ("gocode.rc0.platform-scope-mapping-policy/1", "rc0-platform-scope-mapping-policy-v1.schema.json"),
    ("gocode.rc0.qualified-declaration/1", "rc0-qualified-declaration-v1.schema.json"),
    ("gocode.rc0.platform-scope-attestation/1", "rc0-platform-scope-attestation-v1.schema.json"),
    ("gocode.rc0.artifact-measurement-record/1", "rc0-artifact-measurement-record-v1.schema.json"),
    ("gocode.rc0.native-host-evidence-record/1", "rc0-native-host-evidence-record-v1.schema.json"),
    ("gocode.rc0.profile-evidence-record/1", "rc0-profile-evidence-record-v1.schema.json"),
    ("gocode.rc0.canary-evidence-record/1", "rc0-canary-evidence-record-v1.schema.json"),
    ("gocode.rc0.policy-activation-intent/1", "rc0-policy-activation-intent-v1.schema.json"),
    ("gocode.rc0.policy-acceptance-receipt/1", "rc0-policy-acceptance-receipt-v1.schema.json"),
    ("gocode.rc0.policy-activation-snapshot/1", "rc0-policy-activation-snapshot-v1.schema.json"),
    ("gocode.rc0.platform-qualified-subject/1", "rc0-platform-qualified-subject-v1.schema.json"),
    ("gocode.release.platform-qualification-matrix/2", "release-platform-qualification-matrix-v2.schema.json"),
    ("gocode.rc0.post-rc0-owner-authority-receipt/1", "post-rc0-owner-authority-receipt-v1.schema.json"),
    ("gocode.v1-platform-scope-claim-migration/1", "v1-platform-scope-claim-migration-v1.schema.json"),
    ("gocode.rc0.post-rc0-platform-composed-universe/1", "post-rc0-platform-composed-universe-v1.schema.json"),
    ("gocode.rc0.post-rc0-reconciliation-receipt/1", "post-rc0-reconciliation-receipt-v1.schema.json"),
    ("gocode.rc0.post-rc0-adjunct-trust-schema-registry/1", "post-rc0-adjunct-trust-schema-registry-v1.schema.json"),
)
ADMIN_ROLE = "POST_RC0_ADJUNCT_REGISTRY_AUTHORITY"
G1_ROLE = "POST_RC0_G1_RECEIPT_AUTHORITY"
OWNER_ROLES = ("runtime_platform_owner", "desktop_platform_owner")
REGISTRY_SCHEMA_ID = "gocode.rc0.post-rc0-adjunct-trust-schema-registry/1"
ACCEPTANCE_SCHEMA_ID = "gocode.governance.platform-decision-acceptance/1"
RECEIPT_SCHEMA_ID = "gocode.rc0.post-rc0-owner-authority-receipt/1"
RUNTIME_ADR_SHA256 = "9370f2c65c353a98a7c15aa752bafc3acf488273d1d39d7ee439a19702d900cd"
DESKTOP_ADR_SHA256 = "24a27f74290bd8f013f323d317d60b89a10c4760d6e85707d8a1eb031b1ceca4"
DECISION_SHA256 = "b1dee8ce2d62cf48d4073cf9e56f262f0c75bfc34a91011119e04e43a7bd6225"
DECISION_SCHEMA_SHA256 = "dba89e59dfa2b9a232203353d45b56e24497353b701d318e9569fc3cb791602f"
ENVELOPE_TIME = {"issued_at": "2023-11-14T22:13:20Z", "not_before": "2023-11-14T22:13:10Z", "expires_at": "2023-11-14T22:13:30Z"}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def g1_decision_sha256(decision_raw: bytes) -> str:
    return _sha(canonical_bytes(loads_canonical(decision_raw)) + b"\n")


def g1_principals() -> dict[str, dict[str, str]]:
    return {role: {"subject_id": f"g1fx-{role}-subject", "controlling_account_id": f"g1fx-{role}-account",
                   "delegated_session_id": f"g1fx-{role}-session", "lane_id": f"g1fx-{role}-lane"} for role in G1_ROLES}


def g1_keypairs() -> dict[str, Ed25519PrivateKey]:
    return {role: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"g1-fixture-ed25519:" + role.encode()).digest())
            for role in SIGNER_ROLES}


def g1_key_ids() -> dict[str, str]:
    return {role: key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for role, key in g1_keypairs().items()}


def g1_fixture_verifier() -> SignatureVerifier:
    keypairs = g1_keypairs()
    # FIXTURE_ADJUNCT_REGISTRY_TEST_ONLY resolves its key via issuer_key_id: a fixture
    # registry cannot be issued by an authority role (REGISTRY_FIXTURE_AUTHORITY_FORBIDDEN); all keys are public fixture constants.
    by_key_id = {g1_key_ids()[role]: key for role, key in keypairs.items()}

    def verify(transcript: bytes, signature: str, profile: str) -> TrustVerification | None:
        if profile != FIXTURE_ONLY:
            return None
        domain_end = 4 + len(b"gocode.external-signed-envelope/1")
        length = int.from_bytes(transcript[domain_end:domain_end + 8], "big")
        unsigned = transcript[domain_end + 8:]
        if len(unsigned) != length:
            return None
        signed = loads_canonical(unsigned)
        if type(signed) is not dict:
            return None
        role = signed.get("issuer_role")
        if type(role) is not str or (role not in keypairs and role != "FIXTURE_ADJUNCT_REGISTRY_TEST_ONLY"):
            return None
        key = keypairs.get(role) or by_key_id.get(signed.get("issuer_key_id"))
        if key is None or signed.get("issuer_key_id") != key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        ).hex():
            return None
        try:
            key.public_key().verify(bytes.fromhex(signature), transcript)
        except Exception:
            return None
        return TrustVerification(
            FIXTURE_ONLY, _sha(transcript), signed["issuer"], signed["issuer_key_id"],
            signed["issuer_key_epoch"], signed["issuer_revocation_epoch"],
            signed["signature_profile_id"],
            PrincipalBinding(signed["issuer_role"], signed["issuer_subject_id"],
                             signed["issuer_controlling_account_id"],
                             signed["issuer_delegated_session_id"], signed["issuer_lane_id"]),
        )

    return verify


def _schema_documents() -> dict[str, bytes]:
    return {schema_id: (ROOT / "docs/schemas" / filename).read_bytes() for schema_id, filename in SCHEMAS}


def _schema_digest(schema_id: str) -> str:
    return _sha(_schema_documents()[schema_id])


def g1_schema_store() -> AdjunctSchemaStore:
    return AdjunctSchemaStore(_schema_documents())


def g1_candidate_adr_bytes() -> tuple[bytes, bytes]:
    runtime_raw = (BUNDLE / "candidate-accepted-adrs/ADR-0027-v1-platform-scope.bytes").read_bytes()
    desktop_raw = (BUNDLE / "candidate-accepted-adrs/ADR-0015-v1-platform-scope.bytes").read_bytes()
    if _sha(runtime_raw) != RUNTIME_ADR_SHA256 or _sha(desktop_raw) != DESKTOP_ADR_SHA256:
        raise AssertionError("g1 candidate ADR bytes digest mismatch")
    return runtime_raw, desktop_raw


def g1_shared_decision() -> tuple[bytes, bytes]:
    decision_raw = canonical_bytes(loads_canonical((BUNDLE / "input/v1-platform-scope-v1.json").read_bytes()))
    schema_raw = (BUNDLE / "input/v1-platform-scope-decision-v1.schema.json").read_bytes()
    if g1_decision_sha256(decision_raw) != DECISION_SHA256 or _sha(schema_raw) != DECISION_SCHEMA_SHA256:
        raise AssertionError("g1 shared decision digest mismatch")
    return decision_raw, schema_raw


def _unsigned_envelope(
    payload_schema_id: str, payload: object, issuer_role: str,
    principal: Mapping[str, str] | None = None, issuer_key_id: str | None = None,
) -> dict[str, object]:
    if principal is None:
        principal = g1_principals()[issuer_role]
    if issuer_key_id is None:
        issuer_key_id = g1_key_ids()[issuer_role]
    return {"schema_version": "gocode.rc0.external-signed-envelope/1",
            "payload_schema_id": payload_schema_id,
            "payload_schema_sha256": _schema_digest(payload_schema_id),
            "payload_sha256": _sha(canonical_bytes(payload)), "payload": payload,
            "issuer": FIXTURE_ONLY, "issuer_key_id": issuer_key_id, "issuer_key_epoch": 7,
            "issuer_subject_id": principal["subject_id"],
            "issuer_controlling_account_id": principal["controlling_account_id"],
            "issuer_delegated_session_id": principal["delegated_session_id"],
            "issuer_lane_id": principal["lane_id"], "issuer_role": issuer_role,
            "issuer_revocation_epoch": 3, "signature_profile_id": FIXTURE_ONLY,
            **ENVELOPE_TIME}


def _sign_envelope(unsigned: Mapping[str, object], role: str) -> bytes:
    return canonical_bytes({**unsigned, "signature": g1_keypairs()[role].sign(signature_transcript(unsigned)).hex()})


def _verify(raw: bytes, now: int) -> VerifiedEnvelope:
    return verify_signed_envelope(raw, g1_schema_store(), g1_fixture_verifier(), now)


def _resign(envelope: VerifiedEnvelope, rebuilt: dict[str, object]) -> VerifiedEnvelope:
    unsigned = dict(rebuilt)
    unsigned.pop("signature", None)
    return _verify(_sign_envelope(unsigned, envelope.issuer_role),
                   timestamp_epoch_seconds(rebuilt["issued_at"]))


def g1_fixture_registry(now: int = NOW) -> VerifiedAdjunctTrustRegistry:
    payload = {
        "schema_version": REGISTRY_SCHEMA_ID, "repository_id": "gocode", "registry_revision": 1,
        "adjunct_schema_digests": sorted(
            [{"schema_id": sid, "schema_sha256": _schema_digest(sid)} for sid, _ in SCHEMAS
             if sid != REGISTRY_SCHEMA_ID], key=lambda item: item["schema_id"]),
        "role_principal_constraints": sorted(
            [{"role_id": role, "principal": principal} for role, principal in g1_principals().items()],
            key=lambda item: item["role_id"]),
        "issued_at": ENVELOPE_TIME["issued_at"], "expires_at": ENVELOPE_TIME["expires_at"],
        "revocation_epoch": 3,
    }
    envelope = _unsigned_envelope(
        REGISTRY_SCHEMA_ID, payload, "FIXTURE_ADJUNCT_REGISTRY_TEST_ONLY",
        principal=g1_principals()[ADMIN_ROLE], issuer_key_id=g1_key_ids()[ADMIN_ROLE],
    )
    raw = _sign_envelope(envelope, ADMIN_ROLE)
    view = verify_signed_envelope(raw, g1_schema_store(), g1_fixture_verifier(), now)
    return verify_adjunct_trust_registry(view, g1_schema_store(), FIXTURE_ONLY, now)


def g1_owner_acceptance(
    domain: str, adr_raw: bytes, decision_raw: bytes, decision_schema_raw: bytes,
    registry: VerifiedAdjunctTrustRegistry, now: int = NOW,
) -> VerifiedEnvelope:
    runtime = domain == "runtime"
    role = "runtime_platform_owner" if runtime else "desktop_platform_owner"
    principal = g1_principals()[role]
    payload = {
        "schema_version": ACCEPTANCE_SCHEMA_ID, "repository_id": "gocode",
        "owner_domain": domain, "owner_subject_id": principal["subject_id"],
        "adr_id": "ADR-0027" if runtime else "ADR-0015",
        "adr_document_sha256": _sha(adr_raw),
        "shared_decision_payload_sha256": g1_decision_sha256(decision_raw),
        "shared_decision_schema_sha256": _sha(decision_schema_raw),
        "acceptance_revision": 1, "accepted_at": ENVELOPE_TIME["issued_at"],
    }
    envelope = _unsigned_envelope(ACCEPTANCE_SCHEMA_ID, payload, role)
    return _verify(_sign_envelope(envelope, role), now)


def g1_receipt_envelope(
    registry: VerifiedAdjunctTrustRegistry,
    runtime_adr_raw: bytes, desktop_adr_raw: bytes,
    decision_raw: bytes, decision_schema_raw: bytes,
    runtime_acceptance: VerifiedEnvelope, desktop_acceptance: VerifiedEnvelope,
    now: int = NOW,
) -> VerifiedEnvelope:
    def acceptance(domain: str, adr_raw: bytes, principal: Mapping[str, str]) -> dict[str, object]:
        return {"owner_domain": domain, "owner_subject_id": principal["subject_id"],
                "owner_controlling_account_id": principal["controlling_account_id"],
                "owner_delegated_session_id": principal["delegated_session_id"],
                "owner_lane_id": principal["lane_id"], "adr_document_sha256": _sha(adr_raw),
                "shared_decision_payload_sha256": g1_decision_sha256(decision_raw),
                "shared_decision_schema_sha256": _sha(decision_schema_raw),
                "accepted_at": ENVELOPE_TIME["issued_at"], "revocation_epoch": 3}
    principals = g1_principals()
    payload = {
        "schema_version": RECEIPT_SCHEMA_ID, "repository_id": "gocode",
        "runtime_adr_document_sha256": _sha(runtime_adr_raw),
        "desktop_adr_document_sha256": _sha(desktop_adr_raw),
        "shared_decision_payload_sha256": g1_decision_sha256(decision_raw),
        "shared_decision_schema_sha256": _sha(decision_schema_raw),
        "runtime_owner_acceptance_envelope_sha256": runtime_acceptance.envelope_sha256,
        "desktop_owner_acceptance_envelope_sha256": desktop_acceptance.envelope_sha256,
        "runtime_owner_acceptance": acceptance("runtime", runtime_adr_raw,
                                              principals["runtime_platform_owner"]),
        "desktop_owner_acceptance": acceptance("desktop", desktop_adr_raw,
                                              principals["desktop_platform_owner"]),
        "adjunct_trust_registry_envelope_sha256": registry.envelope_sha256,
        "adjunct_trust_registry_payload_sha256": registry.payload_sha256,
        "issued_at": ENVELOPE_TIME["issued_at"], "expires_at": ENVELOPE_TIME["expires_at"],
        "revocation_epoch": 3,
    }
    envelope = _unsigned_envelope(RECEIPT_SCHEMA_ID, payload, G1_ROLE)
    return _verify(_sign_envelope(envelope, G1_ROLE), now)


def g1_immutable_retrieval_fixture(target_envelope_sha256: str, retrieved_payload_sha256: str) -> dict[str, object]:
    return {"schema_version": "gocode.rc0.immutable-retrieval-fixture/1", "repository_id": "gocode",
            "retrieval_domain": FIXTURE_ONLY, "origin_uri": "fixture://g1/immutable-origin",
            "target_envelope_sha256": target_envelope_sha256,
            "retrieved_payload_sha256": retrieved_payload_sha256}


def replace_envelope_field(envelope: VerifiedEnvelope, field: str, value: object) -> VerifiedEnvelope:
    rebuilt = loads_canonical(envelope.envelope_canonical_bytes)
    if field == "payload":
        rebuilt["payload"] = value
        rebuilt["payload_sha256"] = _sha(canonical_bytes(value))
    else:
        rebuilt[field] = value
    return _resign(envelope, rebuilt)


def mutate_payload_digest(envelope: VerifiedEnvelope, field: str, value: str) -> VerifiedEnvelope:
    payload = loads_canonical(envelope.payload_canonical_bytes)
    payload[field] = value
    rebuilt = loads_canonical(envelope.envelope_canonical_bytes)
    rebuilt["payload"] = payload
    rebuilt["payload_sha256"] = _sha(canonical_bytes(payload))
    return _resign(envelope, rebuilt)
