"""Authenticated fixture evidence joins for platform-scope attestations."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from scripts.rc0_policy.adjunct_registry import VerifiedAdjunctTrustRegistry
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, PrincipalBinding, VerifiedEnvelope, require_fixture_verified
from scripts.rc0_policy.platform_attestation_profiles import AuthenticatedProfileEvidence, AttestationFailure, HostControlResult

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = {"gocode.rc0.artifact-measurement-record/1": "rc0-artifact-measurement-record-v1.schema.json", "gocode.rc0.native-host-evidence-record/1": "rc0-native-host-evidence-record-v1.schema.json", "gocode.rc0.profile-evidence-record/1": "rc0-profile-evidence-record-v1.schema.json", "gocode.rc0.canary-evidence-record/1": "rc0-canary-evidence-record-v1.schema.json"}
ROLES = {"gocode.rc0.artifact-measurement-record/1": frozenset(("artifact_classifier_a", "artifact_classifier_b")), "gocode.rc0.native-host-evidence-record/1": frozenset(("native_host_attestor",)), "gocode.rc0.profile-evidence-record/1": frozenset(("native_host_attestor",)), "gocode.rc0.canary-evidence-record/1": frozenset(("external_canary_operator",))}

@dataclass(frozen=True)
class ExecutedArtifact:
    artifact_slot_id: str; artifact_kind: str; relative_path: str; artifact_sha256: str; size: int; locator: str; artifact_manifest_payload_sha256: str; product_manifest_payload_sha256: str
@dataclass(frozen=True)
class HostIdentity:
    os_family: str; os_version: str; os_build: str; kernel_or_image_sha256: str; architecture: str; native_mode: str; backend_id: str; backend_version: str; probe_set_payload_sha256: str; enforcement_descriptor_payload_sha256: str; workflow_run_id: str; observed_at: str; freshness_deadline: str; executed_artifacts: tuple[ExecutedArtifact, ...]; control_results: tuple[HostControlResult, ...]; host_attestor_identity: PrincipalBinding
@dataclass(frozen=True)
class AttestationEvidenceBundle:
    classifier_pairs: Sequence[tuple[VerifiedEnvelope, VerifiedEnvelope]]; host_records: Sequence[VerifiedEnvelope]; profile_records: Sequence[VerifiedEnvelope]; canary_records: Sequence[VerifiedEnvelope]
def _fail(code: str) -> None: raise AttestationFailure(code)
def principal(value: VerifiedEnvelope) -> PrincipalBinding:
    fields = (value.issuer_role, value.issuer_subject_id, value.issuer_controlling_account_id, value.issuer_delegated_session_id, value.issuer_lane_id)
    if any(type(item) is not str or not item for item in fields) or type(value.trust.principal) is not PrincipalBinding or fields != (value.trust.principal.role_id, value.trust.principal.subject_id, value.trust.principal.controlling_account_id, value.trust.principal.delegated_session_id, value.trust.principal.lane_id): _fail("EVIDENCE_PRINCIPAL_MISMATCH")
    return PrincipalBinding(*fields)
def _store(registry: VerifiedAdjunctTrustRegistry, schema: str) -> AdjunctSchemaStore:
    raw = (ROOT / "docs/schemas" / SCHEMAS[schema]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != dict(registry.adjunct_schema_digests).get(schema): _fail("REGISTRY_SCHEMA_MISMATCH")
    return AdjunctSchemaStore({schema: raw})
def evidence_record(value: object, registry: VerifiedAdjunctTrustRegistry, schema: str) -> tuple[dict[str, object], PrincipalBinding]:
    if type(value) is not VerifiedEnvelope or schema not in SCHEMAS: _fail("EVIDENCE_ENVELOPE_INVALID")
    try:
        require_fixture_verified(value); payload = loads_canonical(value.payload_canonical_bytes); _store(registry, schema).validate(schema, value.payload_schema_sha256, payload)
    except AttestationFailure: raise
    except Exception as error: raise AttestationFailure("EVIDENCE_ENVELOPE_INVALID") from error
    identity, expected = principal(value), dict(registry.role_principal_constraints).get(value.issuer_role)
    if value.payload_schema_id != schema or value.payload_sha256 != hashlib.sha256(value.payload_canonical_bytes).hexdigest() or canonical_bytes(payload) != value.payload_canonical_bytes or value.issuer_role not in ROLES[schema] or expected is None or identity != expected: _fail("EVIDENCE_ROLE_MISMATCH")
    return payload, identity
def groups(bundle: object) -> tuple[tuple[str, tuple[VerifiedEnvelope, ...]], ...]:
    if type(bundle) is not AttestationEvidenceBundle: _fail("EVIDENCE_BUNDLE_INVALID")
    pairs, hosts, profiles, canaries = bundle.classifier_pairs, bundle.host_records, bundle.profile_records, bundle.canary_records
    if any(type(value) not in (tuple, list) for value in (pairs, hosts, profiles, canaries)) or any(type(pair) is not tuple or len(pair) != 2 or any(type(item) is not VerifiedEnvelope for item in pair) for pair in pairs) or any(type(item) is not VerifiedEnvelope for group in (hosts, profiles, canaries) for item in group): _fail("EVIDENCE_BUNDLE_INVALID")
    return (("artifact_measurements", tuple(item for pair in pairs for item in pair)), ("host_evidence_records", tuple(hosts)), ("profile_evidence_records", tuple(profiles)), ("canary_evidence_records", tuple(canaries)))
def digests(bundle: object) -> tuple[tuple[str, tuple[str, ...]], ...]: return tuple((name, tuple(sorted(item.envelope_sha256 for item in values))) for name, values in groups(bundle))
def source(bundle: object) -> tuple[tuple[str, tuple[bytes, ...]], ...]: return tuple((name, tuple(item.envelope_canonical_bytes for item in sorted(values, key=lambda item: item.envelope_sha256))) for name, values in groups(bundle))
def profiles(records: Sequence[VerifiedEnvelope], registry: VerifiedAdjunctTrustRegistry, schema: str) -> tuple[AuthenticatedProfileEvidence, ...]: return tuple(AuthenticatedProfileEvidence(*((lambda x: (x[0], item.envelope_sha256, x[1]))(evidence_record(item, registry, schema)))) for item in records)
def host(payload: dict[str, object], identity: PrincipalBinding, controls: tuple[object, ...]) -> HostIdentity:
    names = ("os_family", "os_version", "os_build", "kernel_or_image_sha256", "architecture", "native_mode", "backend_id", "backend_version", "probe_set_payload_sha256", "enforcement_descriptor_payload_sha256", "workflow_run_id", "observed_at", "freshness_deadline")
    if any(type(payload.get(name)) is not str for name in names) or type(payload.get("executed_artifacts")) is not list: _fail("HOST_EVIDENCE_MISMATCH")
    result = []
    for row in payload["executed_artifacts"]:
        fields = ("artifact_slot_id", "artifact_kind", "relative_path", "sha256", "size", "locator", "artifact_manifest_payload_sha256", "product_manifest_payload_sha256")
        if type(row) is not dict or set(row) != set(fields) or any(type(row[key]) is not str for key in fields if key != "size") or type(row["size"]) is not int or isinstance(row["size"], bool): _fail("HOST_EVIDENCE_MISMATCH")
        result.append(ExecutedArtifact(row["artifact_slot_id"], row["artifact_kind"], row["relative_path"], row["sha256"], row["size"], row["locator"], row["artifact_manifest_payload_sha256"], row["product_manifest_payload_sha256"]))
    return HostIdentity(*(payload[name] for name in names), tuple(result), controls, identity)
