"""Verification-only reconciliation receipt boundary for owner-provided trust."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from scripts.rc0_policy.canonical import loads_canonical
from scripts.rc0_policy.external_envelope import (
    AdjunctSchemaStore,
    PrincipalBinding,
    SignatureVerifier,
    TrustVerification,
    VerifiedEnvelope,
    verify_signed_envelope,
)
from scripts.rc0_policy.adjunct_registry import VerifiedAdjunctTrustRegistry


RECEIPT_SCHEMA_ID = "gocode.rc0.post-rc0-reconciliation-receipt/1"
RECONCILIATION_ROLE = "POST_RC0_RECONCILIATION_AUTHORITY"
_RECEIPT_VERIFIER_TOKEN = object()


class ReconciliationFailure(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ReceiptBoundMarkdownEntry:
    path: str
    blob_oid: str
    mode: Literal["100644"]


@dataclass(frozen=True)
class PreSignedReconciliationNegative:
    vector_id: Literal[
        "unregistered_role", "subject_substitution", "account_substitution",
        "session_substitution", "lane_substitution", "stale", "revoked",
    ]
    raw: bytes
    expected_code: str


@dataclass(frozen=True)
class OwnerReconciliationContext:
    raw: bytes
    schemas: AdjunctSchemaStore
    verify_signature: SignatureVerifier
    adjunct_trust: VerifiedAdjunctTrustRegistry
    now_epoch_seconds: int
    negative_vectors: tuple[PreSignedReconciliationNegative, ...]

    def __post_init__(self) -> None:
        if type(self.raw) is not bytes or type(self.schemas) is not AdjunctSchemaStore:
            raise TypeError("owner context requires raw bytes and a schema store")
        if not callable(self.verify_signature) or type(self.now_epoch_seconds) is not int or isinstance(self.now_epoch_seconds, bool):
            raise TypeError("owner context requires a verifier and integer time")
        if type(self.adjunct_trust) is not VerifiedAdjunctTrustRegistry:
            raise TypeError("owner context requires verified production adjunct trust")
        self.adjunct_trust._require_verified(self.now_epoch_seconds)
        if self.adjunct_trust.verification_domain != "PRODUCTION" or type(self.adjunct_trust.trust) is not TrustVerification:
            raise TypeError("owner context requires verified production adjunct trust")
        if type(self.negative_vectors) is not tuple or any(type(item) is not PreSignedReconciliationNegative for item in self.negative_vectors):
            raise TypeError("owner context requires immutable negative receipts")


class OwnerReconciliationContextBlocked(RuntimeError):
    code = "EXTERNAL_RECONCILIATION_AUTHORITY_UNAVAILABLE"


class VerifiedReconciliationReceipt:
    __slots__ = (
        "envelope_sha256", "reconciled_integration_commit_sha",
        "reconciled_integration_tree_sha", "merge_base_sha", "bound_markdown_entries",
        "classified_path_decisions", "issuer_identity", "issuer_role", "trust",
        "issued_at", "expires_at", "revocation_epoch",
    )
    _FIELD_NAMES = frozenset(__slots__)

    def __new__(cls, verifier_token: object, /, **fields: object) -> "VerifiedReconciliationReceipt":
        if verifier_token is not _RECEIPT_VERIFIER_TOKEN:
            raise TypeError("VerifiedReconciliationReceipt is verifier-owned")
        return super().__new__(cls)

    def __init__(self, verifier_token: object, /, **fields: object) -> None:
        if verifier_token is not _RECEIPT_VERIFIER_TOKEN:
            raise TypeError("VerifiedReconciliationReceipt is verifier-owned")
        if set(fields) != self._FIELD_NAMES:
            raise TypeError("VerifiedReconciliationReceipt requires verified fields")
        for name, value in fields.items():
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("VerifiedReconciliationReceipt is immutable")

    @classmethod
    def _from_verified(
        cls, verifier_token: object, /, envelope: VerifiedEnvelope,
        adjunct_trust: VerifiedAdjunctTrustRegistry,
    ) -> "VerifiedReconciliationReceipt":
        if verifier_token is not _RECEIPT_VERIFIER_TOKEN:
            raise TypeError("VerifiedReconciliationReceipt is verifier-owned")
        return cls(verifier_token, **_receipt_fields_from_verified_envelope(envelope, adjunct_trust))


def _payload(envelope: VerifiedEnvelope) -> dict[str, object]:
    try:
        value = loads_canonical(envelope.payload_canonical_bytes)
    except ValueError as error:
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID") from error
    if type(value) is not dict:
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    return value


def _sorted_entries(values: object) -> tuple[ReceiptBoundMarkdownEntry, ...]:
    if type(values) is not list:
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    result: list[ReceiptBoundMarkdownEntry] = []
    for value in values:
        if type(value) is not dict or set(value) != {"path", "blob_oid", "mode"}:
            raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
        if not all(type(value[key]) is str and value[key] for key in value) or value["mode"] != "100644":
            raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
        result.append(ReceiptBoundMarkdownEntry(value["path"], value["blob_oid"], value["mode"]))
    paths = tuple(entry.path for entry in result)
    if not result or paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    return tuple(result)


def _decisions(values: object) -> tuple[tuple[str, str, str], ...]:
    if type(values) is not list:
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    result: list[tuple[str, str, str]] = []
    for value in values:
        if type(value) is not dict or set(value) != {"path", "classification", "reason"}:
            raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
        if any(type(value[key]) is not str or not value[key] for key in value):
            raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
        result.append((value["path"], value["classification"], value["reason"]))
    paths = tuple(item[0] for item in result)
    if not result or paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    return tuple(result)


def _receipt_fields_from_verified_envelope(
    envelope: VerifiedEnvelope, adjunct_trust: VerifiedAdjunctTrustRegistry,
) -> dict[str, object]:
    payload = _payload(envelope)
    outer = loads_canonical(envelope.envelope_canonical_bytes)
    required = {
        "schema_version", "repository_id", "reconciled_integration_commit_sha",
        "reconciled_integration_tree_sha", "merge_base_sha", "bound_markdown_entries",
        "classified_path_decisions", "issuer_identity", "issuer_role", "trust",
        "issued_at", "expires_at", "revocation_epoch",
    }
    if type(outer) is not dict or set(payload) != required or payload["schema_version"] != RECEIPT_SCHEMA_ID or payload["repository_id"] != "gocode":
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    if any(type(payload[name]) is not str or not payload[name] for name in (
        "reconciled_integration_commit_sha", "reconciled_integration_tree_sha", "merge_base_sha",
        "issued_at", "expires_at",
    )) or type(payload["revocation_epoch"]) is not int:
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    if payload["issued_at"] != outer.get("issued_at") or payload["expires_at"] != outer.get("expires_at"):
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    identity = payload.get("issuer_identity")
    if type(identity) is not dict or set(identity) != {
        "subject_id", "controlling_account_id", "delegated_session_id", "lane_id"
    } or any(type(value) is not str or not value for value in identity.values()):
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    principal = PrincipalBinding(RECONCILIATION_ROLE, **identity)
    trust = envelope.trust
    if envelope.issuer_role != RECONCILIATION_ROLE:
        raise ReconciliationFailure("RECONCILIATION_ROLE_UNREGISTERED")
    if payload.get("issuer_role") != RECONCILIATION_ROLE or principal != adjunct_trust.reconciliation_authority:
        raise ReconciliationFailure("RECONCILIATION_PRINCIPAL_MISMATCH")
    if trust.principal != principal or envelope.issuer_role != RECONCILIATION_ROLE:
        raise ReconciliationFailure("RECONCILIATION_PRINCIPAL_MISMATCH")
    receipt_trust = payload.get("trust")
    expected_trust = {
        "verification_domain": trust.verification_domain, "transcript_sha256": trust.transcript_sha256,
        "issuer": trust.issuer, "issuer_key_id": trust.issuer_key_id,
        "issuer_key_epoch": trust.issuer_key_epoch, "issuer_revocation_epoch": trust.issuer_revocation_epoch,
        "signature_profile_id": trust.signature_profile_id,
    }
    if receipt_trust != expected_trust:
        raise ReconciliationFailure("RECONCILIATION_PRINCIPAL_MISMATCH")
    if payload.get("revocation_epoch") != trust.issuer_revocation_epoch:
        raise ReconciliationFailure("RECONCILIATION_TRUST_REVOKED")
    return {
        "envelope_sha256": envelope.envelope_sha256,
        "reconciled_integration_commit_sha": payload.get("reconciled_integration_commit_sha"),
        "reconciled_integration_tree_sha": payload.get("reconciled_integration_tree_sha"),
        "merge_base_sha": payload.get("merge_base_sha"),
        "bound_markdown_entries": _sorted_entries(payload.get("bound_markdown_entries")),
        "classified_path_decisions": _decisions(payload.get("classified_path_decisions")),
        "issuer_identity": principal, "issuer_role": RECONCILIATION_ROLE, "trust": trust,
        "issued_at": payload.get("issued_at"), "expires_at": payload.get("expires_at"),
        "revocation_epoch": payload.get("revocation_epoch"),
    }


def verify_reconciliation_receipt(
    raw: bytes, schemas: AdjunctSchemaStore, verify_signature: SignatureVerifier,
    adjunct_trust: VerifiedAdjunctTrustRegistry, now_epoch_seconds: int,
) -> VerifiedReconciliationReceipt:
    """Verify raw production evidence; this function has no authority side effects."""
    if type(adjunct_trust) is not VerifiedAdjunctTrustRegistry:
        raise ReconciliationFailure("RECONCILIATION_REGISTRY_INVALID")
    try:
        adjunct_trust.require_verified(now_epoch_seconds)
    except ValueError as error:
        raise ReconciliationFailure("RECONCILIATION_REGISTRY_INVALID") from error
    try:
        parsed = loads_canonical(raw)
    except ValueError as error:
        raise ReconciliationFailure("RECONCILIATION_PARSE_INVALID") from error
    if type(parsed) is not dict:
        raise ReconciliationFailure("RECONCILIATION_PARSE_INVALID")
    try:
        envelope = verify_signed_envelope(raw, schemas, verify_signature, now_epoch_seconds)
    except ValueError as error:
        if getattr(error, "code", None) == "TIME_INVALID":
            raise ReconciliationFailure("RECONCILIATION_TRUST_STALE") from error
        raise ReconciliationFailure("RECONCILIATION_ENVELOPE_INVALID") from error
    if envelope.verification_domain != "PRODUCTION" or envelope.issuer == "FIXTURE_ONLY" or envelope.signature_profile_id == "FIXTURE_ONLY":
        raise ReconciliationFailure("RECONCILIATION_PRODUCTION_REQUIRED")
    if adjunct_trust.verification_domain != "PRODUCTION" or type(adjunct_trust.trust) is not TrustVerification:
        raise ReconciliationFailure("RECONCILIATION_REGISTRY_INVALID")
    if envelope.payload_schema_id != RECEIPT_SCHEMA_ID or dict(adjunct_trust.adjunct_schema_digests).get(RECEIPT_SCHEMA_ID) != envelope.payload_schema_sha256:
        raise ReconciliationFailure("RECONCILIATION_PAYLOAD_INVALID")
    return VerifiedReconciliationReceipt._from_verified(_RECEIPT_VERIFIER_TOKEN, envelope, adjunct_trust)
