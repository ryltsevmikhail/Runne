"""Closed structural contracts for the solo-owner post-RC0 lineage.

These validators deliberately do not grant authority: receipt signature and
immutable-document verification remain the project-owner authority boundary.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.rc0_policy.adjunct_schema_validation import validate_adjunct_schema_instance


ROOT = Path(__file__).resolve().parents[2]
_CONTRACTS = (
    ("registry", "gocode.rc0.post-rc0-adjunct-trust-schema-registry/2", "post-rc0-adjunct-trust-schema-registry-v2.schema.json"),
    ("mapping", "gocode.rc0.platform-scope-mapping-policy/2", "rc0-platform-scope-mapping-policy-v2.schema.json"),
    ("intent", "gocode.rc0.policy-activation-intent/2", "rc0-policy-activation-intent-v2.schema.json"),
    ("snapshot", "gocode.rc0.policy-activation-snapshot/2", "rc0-policy-activation-snapshot-v2.schema.json"),
    ("subject", "gocode.rc0.platform-qualified-subject/2", "rc0-platform-qualified-subject-v2.schema.json"),
    ("matrix", "gocode.release.platform-qualification-matrix/3", "release-platform-qualification-matrix-v3.schema.json"),
)
_BY_KIND = {kind: (schema_id, filename) for kind, schema_id, filename in _CONTRACTS}
_FORBIDDEN_PRINCIPAL_FIELDS = frozenset((
    "role_principal_constraints", "runtime_platform_owner", "desktop_platform_owner",
    "issuer_role", "issuer_subject_id", "issuer_controlling_account_id",
    "issuer_delegated_session_id", "issuer_lane_id",
))


class SuccessorContractFailure(ValueError):
    """The untrusted successor payload is outside the closed contract."""


def successor_schema_ids() -> tuple[str, ...]:
    """Return the sole schema identifiers admitted by this successor lineage."""
    return tuple(schema_id for _, schema_id, _ in _CONTRACTS)


def successor_schema_sha256(kind: str) -> str:
    """Return a schema digest for building a separately signed registry."""
    _, filename = _contract(kind)
    return hashlib.sha256((ROOT / "docs/schemas" / filename).read_bytes()).hexdigest()


def validate_successor_payload(kind: str, payload: object) -> None:
    """Validate one versioned successor payload without interpreting legacy G1."""
    schema_id, filename = _contract(kind)
    if type(payload) is not dict:
        raise SuccessorContractFailure("SUCCESSOR_PAYLOAD_INVALID")
    keys = frozenset(payload)
    if any(key.startswith("g1_") or "g1_authority" in key for key in keys):
        raise SuccessorContractFailure("SUCCESSOR_G1_FIELD_FORBIDDEN")
    if keys & _FORBIDDEN_PRINCIPAL_FIELDS:
        raise SuccessorContractFailure("SUCCESSOR_PRINCIPAL_FIELD_FORBIDDEN")
    try:
        import json

        raw = (ROOT / "docs/schemas" / filename).read_bytes()
        schema = json.loads(raw)
        if schema.get("$id") != schema_id:
            raise ValueError("schema identity")
        errors = validate_adjunct_schema_instance(schema, payload)
    except (OSError, TypeError, ValueError) as error:
        raise SuccessorContractFailure("SUCCESSOR_PAYLOAD_INVALID") from error
    if errors:
        raise SuccessorContractFailure("SUCCESSOR_PAYLOAD_INVALID")
    if kind == "registry":
        entries = payload["adjunct_schema_digests"]
        schema_ids = tuple(item["schema_id"] for item in entries)
        expected = successor_schema_ids()[1:]
        if schema_ids != expected:
            raise SuccessorContractFailure("SUCCESSOR_REGISTRY_SCHEMA_SET_INVALID")
        actual = tuple(successor_schema_sha256(item_kind) for item_kind in _lineage_kinds())
        supplied = tuple(item["schema_sha256"] for item in entries)
        if supplied != actual:
            raise SuccessorContractFailure("SUCCESSOR_REGISTRY_SCHEMA_DIGEST_INVALID")


def validate_successor_lineage(payloads: object) -> None:
    """Validate structural successor links; this does not authorize any artifact."""
    expected_kinds = ("registry", "mapping", "intent", "snapshot", "subject", "matrix")
    if type(payloads) is not dict or tuple(payloads) != expected_kinds:
        raise SuccessorContractFailure("SUCCESSOR_LINEAGE_INVALID")
    receipt_hash: object | None = None
    for kind in expected_kinds:
        payload = payloads[kind]
        validate_successor_payload(kind, payload)
        assert type(payload) is dict
        current = payload["project_owner_authority_receipt_sha256"]
        if receipt_hash is None:
            receipt_hash = current
        elif current != receipt_hash:
            raise SuccessorContractFailure("SUCCESSOR_RECEIPT_LINEAGE_MISMATCH")
    registry, mapping, intent, snapshot, subject, matrix = (
        payloads[kind] for kind in expected_kinds
    )
    assert all(type(value) is dict for value in (registry, mapping, intent, snapshot, subject, matrix))
    expected_links = (
        (mapping["adjunct_trust_schema_registry_envelope_sha256"], registry["adjunct_trust_schema_registry_envelope_sha256"]),
        (intent["mapping_policy_envelope_sha256"], mapping["mapping_policy_envelope_sha256"]),
        (snapshot["mapping_policy_envelope_sha256"], mapping["mapping_policy_envelope_sha256"]),
        (snapshot["activation_intent_envelope_sha256"], intent["activation_intent_envelope_sha256"]),
        (subject["mapping_policy_envelope_sha256"], mapping["mapping_policy_envelope_sha256"]),
        (subject["active_activation_snapshot_envelope_sha256"], snapshot["activation_snapshot_envelope_sha256"]),
        (matrix["platform_qualified_subject_envelope_sha256"], subject["platform_qualified_subject_envelope_sha256"]),
    )
    if any(actual != expected for actual, expected in expected_links):
        raise SuccessorContractFailure("SUCCESSOR_LINEAGE_LINK_INVALID")


def _lineage_kinds() -> tuple[str, ...]:
    return ("mapping", "intent", "snapshot", "subject", "matrix")


def _contract(kind: str) -> tuple[str, str]:
    if type(kind) is not str or kind not in _BY_KIND:
        raise SuccessorContractFailure("SUCCESSOR_CONTRACT_KIND_INVALID")
    return _BY_KIND[kind]
