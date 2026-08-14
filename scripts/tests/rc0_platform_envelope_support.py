"""Private fixture construction for the post-RC0 external-envelope tests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import (
    AdjunctSchemaStore, PrincipalBinding, SignatureVerifier, TrustVerification,
    signature_transcript,
)


__all__ = ("fixture_sign", "different_value", "valid_fixture_envelope")


_NOW = 1_700_000_000
_ROOT = Path(__file__).resolve().parents[2]
_VALID = _ROOT / "scripts/rc0_policy/fixtures/platform_scope/v1/valid"
_REGISTRY_ID = "gocode.rc0.post-rc0-adjunct-trust-schema-registry/1"
_LABEL = b"gocode-test-fixture-envelope-v1"
_SCHEMAS = (
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
    (_REGISTRY_ID, "post-rc0-adjunct-trust-schema-registry-v1.schema.json"),
)


def _schema_documents() -> dict[str, bytes]:
    root = _ROOT / "docs/schemas"
    return {schema_id: (root / filename).read_bytes() for schema_id, filename in _SCHEMAS}


def _schema_digest(schema_id: str) -> str:
    return hashlib.sha256(_schema_documents()[schema_id]).hexdigest()


def _fixture_schema_store() -> AdjunctSchemaStore:
    return AdjunctSchemaStore(_schema_documents())


def _fixture_registry_payload() -> dict[str, object]:
    value = loads_canonical((_VALID / "fixture-adjunct-trust-schema-registry-v1.json").read_bytes())
    if type(value) is not dict:
        raise TypeError("fixture registry payload must be an object")
    return value


def fixture_sign(unsigned: Mapping[str, object]) -> str:
    return _fixture_signature(signature_transcript(unsigned))


def _fixture_signature(transcript: bytes) -> str:
    return hashlib.sha256(_LABEL + transcript).hexdigest()


def different_value(field: str, current: object) -> object:
    timestamps = {
        "issued_at": "2023-11-14T22:13:21Z", "not_before": "2023-11-14T22:13:11Z",
        "expires_at": "2023-11-14T22:13:31Z",
    }
    if field in timestamps:
        return timestamps[field]
    if type(current) is int:
        return current + 1
    if type(current) is str:
        return current + "-changed"
    raise TypeError(f"no mutation fixture for {field}")


def _fixture_envelope(payload: object | None = None) -> dict[str, object]:
    body = _fixture_registry_payload() if payload is None else payload
    return {
        "schema_version": "gocode.rc0.external-signed-envelope/1",
        "payload_schema_id": _REGISTRY_ID,
        "payload_schema_sha256": _schema_digest(_REGISTRY_ID),
        "payload_sha256": hashlib.sha256(canonical_bytes(body)).hexdigest(),
        "payload": body,
        "issuer": "FIXTURE_ONLY", "issuer_key_id": "fixture-key-1", "issuer_key_epoch": 7,
        "issuer_subject_id": "fixture-envelope-subject", "issuer_controlling_account_id": "fixture-envelope-account",
        "issuer_delegated_session_id": "fixture-envelope-session", "issuer_lane_id": "fixture-envelope-lane",
        "issuer_role": "FIXTURE_ADJUNCT_REGISTRY_TEST_ONLY", "issuer_revocation_epoch": 3,
        "signature_profile_id": "FIXTURE_ONLY", "issued_at": "2023-11-14T22:13:20Z",
        "not_before": "2023-11-14T22:13:10Z", "expires_at": "2023-11-14T22:13:30Z", "signature": "",
    }


def _sign(envelope: dict[str, object]) -> bytes:
    unsigned = dict(envelope)
    unsigned.pop("signature", None)
    envelope["signature"] = fixture_sign(unsigned)
    return canonical_bytes(envelope)


def _signed_fixture_envelope(payload: object) -> bytes:
    return _sign(_fixture_envelope(payload))


def valid_fixture_envelope() -> tuple[bytes, SignatureVerifier]:
    raw = _sign(_fixture_envelope())

    def verifier(transcript: bytes, signature: str, profile: str) -> TrustVerification | None:
        if profile != "FIXTURE_ONLY" or signature != _fixture_signature(transcript):
            return None
        domain_end = 4 + len(b"gocode.external-signed-envelope/1")
        length = int.from_bytes(transcript[domain_end:domain_end + 8], "big")
        unsigned = transcript[domain_end + 8:]
        if len(unsigned) != length:
            return None
        signed = loads_canonical(unsigned)
        if type(signed) is not dict:
            return None
        principal = PrincipalBinding(
            signed["issuer_role"], signed["issuer_subject_id"], signed["issuer_controlling_account_id"],
            signed["issuer_delegated_session_id"], signed["issuer_lane_id"],
        )
        return TrustVerification("FIXTURE_ONLY", hashlib.sha256(transcript).hexdigest(), signed["issuer"], signed["issuer_key_id"], signed["issuer_key_epoch"], signed["issuer_revocation_epoch"], signed["signature_profile_id"], principal)

    return raw, verifier
