"""Immutable fixture-only mapping, policy, and lineage verifier."""

from __future__ import annotations

import hashlib
import re
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from scripts.rc0_policy.adjunct_registry import VerifiedAdjunctTrustRegistry
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, PrincipalBinding, VerifiedEnvelope, require_fixture_verified, signature_transcript, timestamp_epoch_seconds
from scripts.rc0_policy.governance_status import GovernanceStatusFailure, accepted_adr_digests, parse_accepted_adr
from scripts.rc0_policy.platform_policy_errors import PolicyFailure
from scripts.rc0_policy.rules import validate_policy_inventory
from scripts.rc0_policy.schemas import SCHEMA_FILES, validate_schema


ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "scripts/rc0_policy/fixtures/platform_scope/v1/valid"
_TOKEN = object()
_ROWS_PATH = re.compile(r"(?!/)(?!.*//)(?!.*(?:^|/)\.\.?/)[^\x00]+\.(?:md|markdown)")
_SCHEMA_PATHS = {
    "gocode.rc0.platform-scope-mapping-policy/1": "rc0-platform-scope-mapping-policy-v1.schema.json",
    "gocode.governance.platform-decision-acceptance/1": "platform-decision-acceptance-v1.schema.json",
    "gocode.rc0.post-rc0-platform-composed-universe/1": "post-rc0-platform-composed-universe-v1.schema.json",
    "gocode.v1-platform-scope-claim-migration/1": "v1-platform-scope-claim-migration-v1.schema.json",
}


@dataclass(frozen=True)
class AuthorityRoleBinding: role_id: str; principals: tuple[PrincipalBinding, ...]
@dataclass(frozen=True)
class PlatformScopePolicyRow: platform_scope_id: str; qualification_class: str; support_disposition: str; os_family: str; os_version: str; architecture: str
@dataclass(frozen=True)
class ArtifactSlotPolicyRow: platform_scope_id: str; artifact_slot_id: str; artifact_kind: str
@dataclass(frozen=True)
class HostPolicyRow: platform_scope_id: str; os_build: str; kernel_or_image_sha256: str; backend_id: str; backend_version: str; probe_set_payload_sha256: str; enforcement_descriptor_payload_sha256: str
@dataclass(frozen=True)
class ProfileStatePolicyRow: platform_scope_id: str; profile_id: str; profile_revision: int | str; profile_sha256: str | None; state: str
@dataclass(frozen=True)
class Rc0TrustPolicyView:
    rc0_qualification_policy_digest: str; canonical_bytes: bytes; canonical_sha256: str
    schema_id_hash_pairs: tuple[tuple[str, str], ...]; required_gate_projection: tuple[tuple[str, str, str, str, str], ...]; legacy_issuer_role_strings: tuple[str, ...]


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class VerifiedMappingPolicy:
    envelope_sha256: str; adjunct_trust_registry_envelope_sha256: str; adjunct_trust_registry_payload_sha256: str; adjunct_trust: VerifiedAdjunctTrustRegistry; rc0_qualification_policy_digest: str; shared_decision_payload_sha256: str; claim_registry_payload_sha256: str; base_document_universe_payload_sha256: str; classified_delta_payload_sha256: str; composed_document_universe_payload_sha256: str; activation_epoch: int; platform_scopes: tuple[PlatformScopePolicyRow, ...]; artifact_slots: tuple[ArtifactSlotPolicyRow, ...]; profile_states: tuple[ProfileStatePolicyRow, ...]; host_identity_pins: tuple[HostPolicyRow, HostPolicyRow, HostPolicyRow]; required_gate_ids: tuple[str, ...]; rc0_trust_policy: Rc0TrustPolicyView; mapping_authority: PrincipalBinding; governance_authorities: tuple[PrincipalBinding, PrincipalBinding]; authority_roles: tuple[AuthorityRoleBinding, ...]; adjunct_schema_digests: tuple[tuple[str, str], ...]; _canonical_source_bytes: bytes; _verification_token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_verification_token"}: raise TypeError("VerifiedMappingPolicy is verifier-owned")
        for key, value in fields.items(): object.__setattr__(self, key, value)
        object.__setattr__(self, "_verification_token", token)
    def require_verified(self, now_epoch_seconds: int) -> None:
        if type(self) is not VerifiedMappingPolicy or self._verification_token is not _TOKEN: _fail("MAPPING_VERIFIED_INVALID")
        try:
            state = _STATES.get(self)
            if state is None or state.adjunct_trust is not self.adjunct_trust or type(self.adjunct_trust) is not VerifiedAdjunctTrustRegistry or not _view_types(self): _fail("MAPPING_VERIFIED_INVALID")
            outer = loads_canonical(self._canonical_source_bytes)
            if self._canonical_source_bytes != state.source or _view_digest(self) != state.view_digest or type(outer) is not dict or canonical_bytes(outer) != self._canonical_source_bytes or _sha(self._canonical_source_bytes) != self.envelope_sha256: _fail("MAPPING_VERIFIED_INVALID")
            payload = outer.get("payload")
            if type(payload) is not dict or _sha(canonical_bytes(payload)) != outer.get("payload_sha256") or _trust_frame(outer) != state.trust_frame: _fail("MAPPING_VERIFIED_INVALID")
            _envelope_now(outer, now_epoch_seconds)
            VerifiedAdjunctTrustRegistry.require_verified(self.adjunct_trust, now_epoch_seconds)
            _verify_mapping_view(self, outer, payload)
        except PolicyFailure: raise
        except Exception as error: raise PolicyFailure("MAPPING_VERIFIED_INVALID") from error


def _sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()
def _fail(code: str) -> None: raise PolicyFailure(code)
@dataclass(frozen=True)
class _MappingState: source: bytes; view_digest: str; trust_frame: tuple[object, ...]; adjunct_trust: VerifiedAdjunctTrustRegistry
_STATES: weakref.WeakKeyDictionary[VerifiedMappingPolicy, _MappingState] = weakref.WeakKeyDictionary()
def _envelope_now(outer: dict[str, object], now: int) -> None:
    if type(now) is not int or isinstance(now, bool): _fail("MAPPING_ENVELOPE_TIME_INVALID")
    not_before, issued, expires = (timestamp_epoch_seconds(outer.get(name)) for name in ("not_before", "issued_at", "expires_at"))
    if not not_before <= issued <= now <= expires: _fail("MAPPING_ENVELOPE_TIME_INVALID")
def _trust_frame(outer: dict[str, object]) -> tuple[object, ...]:
    unsigned = dict(outer); signature = unsigned.pop("signature", None)
    keys = ("issuer", "issuer_key_id", "issuer_key_epoch", "issuer_revocation_epoch", "signature_profile_id", "issuer_role", "issuer_subject_id", "issuer_controlling_account_id", "issuer_delegated_session_id", "issuer_lane_id")
    return (signature, _sha(signature_transcript(unsigned)), *(outer.get(key) for key in keys))
def _principal_projection(value: PrincipalBinding) -> list[str]: return [value.role_id, value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id]
def _trust_projection(value: Rc0TrustPolicyView) -> list[object]: return [value.rc0_qualification_policy_digest, _sha(value.canonical_bytes), value.canonical_sha256, [list(pair) for pair in value.schema_id_hash_pairs], [list(row) for row in value.required_gate_projection], list(value.legacy_issuer_role_strings)]
def _view_types(view: VerifiedMappingPolicy) -> bool:
    scalar = (view.envelope_sha256, view.adjunct_trust_registry_envelope_sha256, view.adjunct_trust_registry_payload_sha256, view.rc0_qualification_policy_digest, view.shared_decision_payload_sha256, view.claim_registry_payload_sha256, view.base_document_universe_payload_sha256, view.classified_delta_payload_sha256, view.composed_document_universe_payload_sha256)
    containers = (view.platform_scopes, view.artifact_slots, view.profile_states, view.host_identity_pins, view.required_gate_ids, view.governance_authorities, view.authority_roles, view.adjunct_schema_digests)
    if any(type(value) is not str for value in scalar) or type(view.activation_epoch) is not int or type(view._canonical_source_bytes) is not bytes or any(type(value) is not tuple for value in containers) or len(view.host_identity_pins) != 3 or len(view.governance_authorities) != 2: return False
    if not all(type(row) is PlatformScopePolicyRow for row in view.platform_scopes) or not all(type(row) is ArtifactSlotPolicyRow for row in view.artifact_slots) or not all(type(row) is ProfileStatePolicyRow for row in view.profile_states) or not all(type(row) is HostPolicyRow for row in view.host_identity_pins) or not all(type(value) is str for value in view.required_gate_ids): return False
    if not all(type(row) is PrincipalBinding for row in view.governance_authorities) or type(view.mapping_authority) is not PrincipalBinding or type(view.rc0_trust_policy) is not Rc0TrustPolicyView or not all(type(row) is AuthorityRoleBinding and type(row.role_id) is str and type(row.principals) is tuple and all(type(principal) is PrincipalBinding for principal in row.principals) for row in view.authority_roles) or not all(type(row) is tuple and len(row) == 2 and type(row[0]) is str and type(row[1]) is str for row in view.adjunct_schema_digests): return False
    principals = (view.mapping_authority, *view.governance_authorities, *(principal for role in view.authority_roles for principal in role.principals))
    trust = view.rc0_trust_policy
    return all(all(type(value) is str for value in _principal_projection(row)) for row in principals) and all(all(type(value) is str for value in (row.platform_scope_id, row.qualification_class, row.support_disposition, row.os_family, row.os_version, row.architecture)) for row in view.platform_scopes) and all(all(type(value) is str for value in (row.platform_scope_id, row.artifact_slot_id, row.artifact_kind)) for row in view.artifact_slots) and all(type(row.platform_scope_id) is str and type(row.profile_id) is str and type(row.profile_revision) in {int, str} and (row.profile_sha256 is None or type(row.profile_sha256) is str) and type(row.state) is str for row in view.profile_states) and all(all(type(value) is str for value in (row.platform_scope_id, row.os_build, row.kernel_or_image_sha256, row.backend_id, row.backend_version, row.probe_set_payload_sha256, row.enforcement_descriptor_payload_sha256)) for row in view.host_identity_pins) and type(trust.rc0_qualification_policy_digest) is str and type(trust.canonical_bytes) is bytes and type(trust.canonical_sha256) is str and _sha(trust.canonical_bytes) == trust.canonical_sha256 and type(trust.schema_id_hash_pairs) is tuple and type(trust.required_gate_projection) is tuple and type(trust.legacy_issuer_role_strings) is tuple and all(type(pair) is tuple and len(pair) == 2 and all(type(value) is str for value in pair) for pair in trust.schema_id_hash_pairs) and all(type(row) is tuple and len(row) == 5 and all(type(value) is str for value in row) for row in trust.required_gate_projection) and all(type(value) is str for value in trust.legacy_issuer_role_strings)
def _view_projection(view: VerifiedMappingPolicy) -> dict[str, object]:
    trust = view.rc0_trust_policy
    return {"envelope": view.envelope_sha256, "registry": [view.adjunct_trust_registry_envelope_sha256, view.adjunct_trust_registry_payload_sha256], "policy": view.rc0_qualification_policy_digest, "decision": view.shared_decision_payload_sha256, "lineage": [view.claim_registry_payload_sha256, view.base_document_universe_payload_sha256, view.classified_delta_payload_sha256, view.composed_document_universe_payload_sha256], "activation": view.activation_epoch, "scopes": [[row.platform_scope_id, row.qualification_class, row.support_disposition, row.os_family, row.os_version, row.architecture] for row in view.platform_scopes], "slots": [[row.platform_scope_id, row.artifact_slot_id, row.artifact_kind] for row in view.artifact_slots], "profiles": [[row.platform_scope_id, row.profile_id, row.profile_revision, row.profile_sha256, row.state] for row in view.profile_states], "host_pins": [[row.platform_scope_id, row.os_build, row.kernel_or_image_sha256, row.backend_id, row.backend_version, row.probe_set_payload_sha256, row.enforcement_descriptor_payload_sha256] for row in view.host_identity_pins], "gates": list(view.required_gate_ids), "trust": _trust_projection(trust), "mapping": _principal_projection(view.mapping_authority), "owners": [_principal_projection(row) for row in view.governance_authorities], "roles": [[row.role_id, [_principal_projection(principal) for principal in row.principals]] for row in view.authority_roles], "schemas": [list(row) for row in view.adjunct_schema_digests]}
def _view_digest(view: VerifiedMappingPolicy) -> str: return _sha(canonical_bytes(_view_projection(view)))
def _principal(envelope: VerifiedEnvelope) -> PrincipalBinding: return PrincipalBinding(envelope.issuer_role, envelope.issuer_subject_id, envelope.issuer_controlling_account_id, envelope.issuer_delegated_session_id, envelope.issuer_lane_id)
def _payload(envelope: VerifiedEnvelope) -> dict[str, object]:
    try: require_fixture_verified(envelope); value = loads_canonical(envelope.payload_canonical_bytes)
    except Exception as error: raise PolicyFailure("FIXTURE_ENVELOPE_INVALID") from error
    if type(value) is not dict: _fail("PAYLOAD_INVALID")
    return value
def _registry(registry: VerifiedAdjunctTrustRegistry, role: str) -> PrincipalBinding:
    value = dict(registry.role_principal_constraints).get(role)
    if value is None: _fail("REGISTRY_ROLE_MISMATCH")
    return value
def _store(registry: VerifiedAdjunctTrustRegistry, *schema_ids: str) -> AdjunctSchemaStore:
    digests = dict(registry.adjunct_schema_digests); documents: dict[str, bytes] = {}
    for schema_id in schema_ids:
        path = _SCHEMA_PATHS.get(schema_id)
        raw = (ROOT / "docs/schemas" / path).read_bytes() if path else b""
        if not raw or digests.get(schema_id) != _sha(raw): _fail("REGISTRY_SCHEMA_MISMATCH")
        documents[schema_id] = raw
    return AdjunctSchemaStore(documents)
def _registry_schema(registry: VerifiedAdjunctTrustRegistry, envelope: VerifiedEnvelope, schema_id: str, payload: dict[str, object]) -> None:
    if envelope.payload_schema_id != schema_id or envelope.payload_schema_sha256 != dict(registry.adjunct_schema_digests).get(schema_id): _fail("REGISTRY_SCHEMA_MISMATCH")
    _store(registry, schema_id).validate(schema_id, envelope.payload_schema_sha256, payload)


def _rows(raw: bytes, kind: str) -> list[dict[str, object]]:
    value = loads_canonical(raw)
    if type(value) is not dict or canonical_bytes(value) != raw or set(value) != {"repository_id", "rows", "schema_version"} or value.get("repository_id") != "gocode" or value.get("schema_version") != kind or type(value.get("rows")) is not list: _fail("FIXTURE_LINEAGE_MISMATCH")
    rows = value["rows"]
    if not rows or any(type(row) is not dict or set(row) != {"path", "classification", "content_sha256"} or type(row["path"]) is not str or _ROWS_PATH.fullmatch(row["path"]) is None or type(row["classification"]) is not str or not row["classification"] or type(row["content_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", row["content_sha256"]) is None for row in rows): _fail("FIXTURE_LINEAGE_MISMATCH")
    if rows != sorted(rows, key=lambda row: row["path"]) or len({row["path"] for row in rows}) != len(rows): _fail("FIXTURE_LINEAGE_MISMATCH")
    return rows
def _lineage(registry: VerifiedAdjunctTrustRegistry, claim: bytes, base: bytes, delta: bytes, composed: bytes) -> tuple[str, str, str, str]:
    b, d = _rows(base, "gocode.rc0.fixture-base-document-universe/1"), _rows(delta, "gocode.rc0.fixture-classified-delta/1")
    union = {row["path"]: row for row in b}; union.update({row["path"]: row for row in d})
    projection = canonical_bytes([union[path] for path in sorted(union)])
    c, q = loads_canonical(composed), loads_canonical(claim)
    if canonical_bytes(c) != composed or canonical_bytes(q) != claim: _fail("FIXTURE_LINEAGE_MISMATCH")
    values = (_sha(base), _sha(delta), _sha(projection))
    store = _store(registry, "gocode.rc0.post-rc0-platform-composed-universe/1", "gocode.v1-platform-scope-claim-migration/1")
    try:
        store.validate("gocode.rc0.post-rc0-platform-composed-universe/1", dict(registry.adjunct_schema_digests)["gocode.rc0.post-rc0-platform-composed-universe/1"], c)
        store.validate("gocode.v1-platform-scope-claim-migration/1", dict(registry.adjunct_schema_digests)["gocode.v1-platform-scope-claim-migration/1"], q)
    except Exception as error: raise PolicyFailure("FIXTURE_LINEAGE_MISMATCH") from error
    keys = ("base_document_universe_payload_sha256", "classified_delta_payload_sha256", "composed_document_universe_payload_sha256")
    if any(item.get(key) != digest for item in (c, q) for key, digest in zip(keys, values)) or c.get("base_paths") != [row["path"] for row in b] or c.get("classified_delta_paths") != [row["path"] for row in d] or c.get("composed_paths") != sorted(union): _fail("FIXTURE_LINEAGE_MISMATCH")
    claims, paths = q["claims"], [path for row in q["claims"] for path in row["expected_paths"]]
    if claims != sorted(claims, key=lambda row: row["claim_id"]) or len({row["claim_id"] for row in claims}) != len(claims) or any(row["literal_needles"] != sorted(set(row["literal_needles"])) or row["expected_paths"] != sorted(row["expected_paths"]) for row in claims) or len(set(paths)) != len(paths) or sorted(paths) != c["classified_delta_paths"]: _fail("FIXTURE_LINEAGE_MISMATCH")
    return _sha(claim), *values


def _policy(value: Mapping[str, object]) -> Rc0TrustPolicyView:
    raw = canonical_bytes(dict(value)); expected = canonical_bytes(loads_canonical((VALID / "fixture-rc0-qualification-policy-v1.json").read_bytes()))
    if raw != expected or validate_schema(value, "gocode.rc0.schema.qualification-policy-bundle/3") or validate_policy_inventory(value): _fail("RC0_MAPPING_SET_MISMATCH")
    pairs = tuple(sorted((row["schema_id"], row["sha256"]) for row in value["expected_schema_digests"]))
    actual = tuple(sorted((schema_id, _sha((ROOT / "docs/schemas" / filename).read_bytes())) for schema_id, filename in SCHEMA_FILES.items()))
    if pairs != actual: _fail("RC0_MAPPING_SET_MISMATCH")
    gates = tuple(sorted((row["gate_id"], row["stage"], "PASS", "PASS", "") for row in value["required_gates"]))
    return Rc0TrustPolicyView(value["policy_digest"], raw, _sha(raw), pairs, gates, tuple(value["trusted_evidence_issuers"]))
def _opencode_digest() -> str:
    raw = (ROOT / "docs/profiles/opencode-baseline-inventory-v3.json").read_bytes(); value = loads_canonical(raw)
    schema = (ROOT / "docs/schemas/opencode-baseline-inventory-v3.schema.json").read_bytes()
    digests = value.get("digests") if type(value) is dict else None
    inventory = value.get("inventory") if type(value) is dict else None
    if canonical_bytes(value) != raw or value.get("profile_id") != "opencode-baseline-inventory" or value.get("profile_revision") != 3 or type(digests) is not dict or type(inventory) is not list: _fail("RC0_MAPPING_SET_MISMATCH")
    items, profile_schema = _sha(canonical_bytes(inventory)), _sha(schema)
    if digests.get("inventory_digest") != "sha256:" + items or digests.get("profile_schema_digest") != "sha256:" + profile_schema: _fail("RC0_MAPPING_SET_MISMATCH")
    return _sha(b"gocode.opencode-baseline-inventory-profile-binding/1\0" + canonical_bytes({"profile_id": value["profile_id"], "profile_revision": 3, "inventory_payload_sha256": _sha(raw), "inventory_items_sha256": items, "profile_schema_sha256": profile_schema}))
def _matrix(payload: dict[str, object]) -> tuple[tuple[PlatformScopePolicyRow, ...], tuple[ArtifactSlotPolicyRow, ...], tuple[ProfileStatePolicyRow, ...], tuple[HostPolicyRow, HostPolicyRow, HostPolicyRow]]:
    scopes, slots, profiles = (payload.get(key) for key in ("platform_scopes", "artifact_slot_mappings", "profile_state_matrix"))
    if not all(type(value) is list for value in (scopes, slots, profiles)) or scopes != sorted(scopes, key=lambda row: row["platform_scope_id"]) or slots != sorted(slots, key=lambda row: row["artifact_slot_id"]) or profiles != sorted(profiles, key=lambda row: (row["platform_scope_id"], row["profile_id"])): _fail("RC0_MAPPING_SET_MISMATCH")
    scope_rows = tuple(sorted((PlatformScopePolicyRow(row["platform_scope_id"], row["qualification_class"], row["support_disposition"], row["os_family"], row["os_version"], row["architecture"]) for row in scopes), key=lambda row: row.platform_scope_id))
    expected_scopes = (PlatformScopePolicyRow("linux-ubuntu-24_04-x86_64-production", "production", "supported", "Ubuntu", "24.04", "x86_64"), PlatformScopePolicyRow("macos-14-arm64-development-preview", "development_preview", "supported", "macOS", "14", "arm64"), PlatformScopePolicyRow("windows-11-24h2-x86_64-production", "production", "supported", "Windows", "11-24H2-client", "x86_64"))
    slot_rows = tuple(sorted((ArtifactSlotPolicyRow(row["platform_scope_id"], row["artifact_slot_id"], row["artifact_kind"]) for row in slots), key=lambda row: row.artifact_slot_id))
    expected_slots = (ArtifactSlotPolicyRow("linux-ubuntu-24_04-x86_64-production", "linux-appimage", "appimage"), ArtifactSlotPolicyRow("linux-ubuntu-24_04-x86_64-production", "linux-deb", "deb"), ArtifactSlotPolicyRow("macos-14-arm64-development-preview", "macos-app-development-adhoc", "macos_app_bundle"), ArtifactSlotPolicyRow("macos-14-arm64-development-preview", "macos-dmg-development-adhoc", "dmg"), ArtifactSlotPolicyRow("windows-11-24h2-x86_64-production", "windows-installer-unsigned", "msi"))
    source = {"gocode-local-runtime/2": _sha((ROOT / "contracts/gocode-ui-client-2/bundle.json").read_bytes()), "gocode-openai-responses-text/1": _sha((ROOT / "docs/profiles/openai-responses-text-v1.json").read_bytes()), "opencode-baseline-inventory": _opencode_digest()}
    expected_profiles = []
    for scope in expected_scopes:
        provider = "external_canary_only" if scope.platform_scope_id.startswith("macos") else "required"
        expected_profiles.extend((ProfileStatePolicyRow(scope.platform_scope_id, "gocode-local-runtime/2", 2, source["gocode-local-runtime/2"], "required"), ProfileStatePolicyRow(scope.platform_scope_id, "gocode-openai-responses-text/1", 2, source["gocode-openai-responses-text/1"], provider), ProfileStatePolicyRow(scope.platform_scope_id, "opencode-baseline-inventory", 3, source["opencode-baseline-inventory"], "required"), ProfileStatePolicyRow(scope.platform_scope_id, "v1-rc0-no-local-tools/1", "v1-rc0-no-local-tools/1", None, "disabled_by_policy"), ProfileStatePolicyRow(scope.platform_scope_id, "v1-rc0-no-production-mcp/1", "v1-rc0-no-production-mcp/1", None, "disabled_by_policy"), ProfileStatePolicyRow(scope.platform_scope_id, "gocode-pty/1", "unavailable", None, "backend_unavailable")))
    profile_rows = tuple(sorted((ProfileStatePolicyRow(row["platform_scope_id"], row["profile_id"], row["profile_revision"], row["profile_sha256"], row["state"]) for row in profiles), key=lambda row: (row.platform_scope_id, row.profile_id)))
    pins = payload.get("host_identity_pins")
    if type(pins) is not list or pins != sorted(pins, key=lambda row: row["platform_scope_id"]): _fail("RC0_MAPPING_SET_MISMATCH")
    pin_rows = tuple(HostPolicyRow(row["platform_scope_id"], row["os_build"], row["kernel_or_image_sha256"], row["backend_id"], row["backend_version"], row["probe_set_payload_sha256"], row["enforcement_descriptor_payload_sha256"]) for row in pins)
    if scope_rows != expected_scopes or slot_rows != expected_slots or profile_rows != tuple(sorted(expected_profiles, key=lambda row: (row.platform_scope_id, row.profile_id))) or len(pin_rows) != 3 or {row.platform_scope_id for row in pin_rows} != {row.platform_scope_id for row in expected_scopes}: _fail("RC0_MAPPING_SET_MISMATCH")
    return scope_rows, slot_rows, profile_rows, pin_rows


def _decision(raw: bytes) -> tuple[dict[str, object], str]:
    try:
        value = loads_canonical(raw); schema_raw = (ROOT / "docs/schemas/v1-platform-scope-decision-v1.schema.json").read_bytes()
        expected = canonical_bytes(loads_canonical((ROOT / "docs/decisions/v1-platform-scope-v1.json").read_bytes()))
    except Exception as error: raise PolicyFailure("SHARED_DECISION_INVALID") from error
    if type(value) is not dict or canonical_bytes(value) != raw or raw != expected: _fail("SHARED_DECISION_INVALID")
    return value, _sha(schema_raw)
def _mapping_values(payload: dict[str, object], trust: Rc0TrustPolicyView, registry: VerifiedAdjunctTrustRegistry) -> tuple[tuple[PlatformScopePolicyRow, ...], tuple[ArtifactSlotPolicyRow, ...], tuple[ProfileStatePolicyRow, ...], tuple[HostPolicyRow, HostPolicyRow, HostPolicyRow], tuple[str, ...]]:
    _store(registry, "gocode.rc0.platform-scope-mapping-policy/1").validate("gocode.rc0.platform-scope-mapping-policy/1", dict(registry.adjunct_schema_digests)["gocode.rc0.platform-scope-mapping-policy/1"], payload)
    scopes, slots, profiles, pins = _matrix(payload)
    gates = tuple(sorted(row["gate_id"] for row in loads_canonical(trust.canonical_bytes)["required_gates"]))
    if any(row.get("required_gate_ids") != list(gates) for row in payload["platform_scopes"]): _fail("RC0_MAPPING_SET_MISMATCH")
    schema_pins = {"attestation_payload_schema_sha256": "gocode.rc0.platform-scope-attestation/1", "qualified_subject_payload_schema_sha256": "gocode.rc0.platform-qualified-subject/1", "matrix_payload_schema_sha256": "gocode.release.platform-qualification-matrix/2"}
    if any(payload.get(key) != dict(registry.adjunct_schema_digests).get(schema_id) for key, schema_id in schema_pins.items()): _fail("REGISTRY_SCHEMA_MISMATCH")
    return scopes, slots, profiles, pins, gates
def _verify_mapping_view(view: VerifiedMappingPolicy, outer: dict[str, object], payload: dict[str, object]) -> None:
    trust = _policy(loads_canonical((VALID / "fixture-rc0-qualification-policy-v1.json").read_bytes()))
    scopes, slots, profiles, pins, gates = _mapping_values(payload, trust, view.adjunct_trust)
    roles = tuple(AuthorityRoleBinding(role, (principal,)) for role, principal in view.adjunct_trust.role_principal_constraints)
    if outer.get("payload_schema_id") != "gocode.rc0.platform-scope-mapping-policy/1" or outer.get("payload_schema_sha256") != dict(view.adjunct_trust.adjunct_schema_digests).get("gocode.rc0.platform-scope-mapping-policy/1") or _sha(canonical_bytes(payload)) != outer.get("payload_sha256"): _fail("MAPPING_VERIFIED_INVALID")
    expected = {"envelope": _sha(view._canonical_source_bytes), "registry": [view.adjunct_trust.envelope_sha256, view.adjunct_trust.payload_sha256], "policy": trust.rc0_qualification_policy_digest, "decision": payload.get("shared_decision_payload_sha256"), "lineage": [payload.get("claim_migration_registry_payload_sha256"), payload.get("base_document_universe_payload_sha256"), payload.get("classified_delta_payload_sha256"), payload.get("composed_document_universe_payload_sha256")], "activation": payload.get("activation_epoch"), "scopes": [[row.platform_scope_id, row.qualification_class, row.support_disposition, row.os_family, row.os_version, row.architecture] for row in scopes], "slots": [[row.platform_scope_id, row.artifact_slot_id, row.artifact_kind] for row in slots], "profiles": [[row.platform_scope_id, row.profile_id, row.profile_revision, row.profile_sha256, row.state] for row in profiles], "host_pins": [[row.platform_scope_id, row.os_build, row.kernel_or_image_sha256, row.backend_id, row.backend_version, row.probe_set_payload_sha256, row.enforcement_descriptor_payload_sha256] for row in pins], "gates": list(gates), "trust": _trust_projection(trust), "mapping": _principal_projection(_principal_from_outer(outer)), "owners": [_principal_projection(_registry(view.adjunct_trust, "runtime_platform_owner")), _principal_projection(_registry(view.adjunct_trust, "desktop_platform_owner"))], "roles": [[row.role_id, [_principal_projection(principal) for principal in row.principals]] for row in roles], "schemas": [list(row) for row in view.adjunct_trust.adjunct_schema_digests]}
    if _view_projection(view) != expected: _fail("MAPPING_VERIFIED_INVALID")
def _principal_from_outer(value: dict[str, object]) -> PrincipalBinding:
    return PrincipalBinding(value.get("issuer_role"), value.get("issuer_subject_id"), value.get("issuer_controlling_account_id"), value.get("issuer_delegated_session_id"), value.get("issuer_lane_id"))


def fixture_verify_mapping_policy(envelope: VerifiedEnvelope, rc0_policy: Mapping[str, object], shared_decision_raw: bytes, runtime_adr_raw: bytes, desktop_adr_raw: bytes, owner_acceptances: Sequence[VerifiedEnvelope], adjunct_trust: VerifiedAdjunctTrustRegistry, claim_registry_raw: bytes, base_document_universe_raw: bytes, classified_delta_raw: bytes, composed_document_universe_raw: bytes, now_epoch_seconds: int) -> VerifiedMappingPolicy:
    if type(adjunct_trust) is not VerifiedAdjunctTrustRegistry: _fail("REGISTRY_FRESHNESS_INVALID")
    try:
        VerifiedAdjunctTrustRegistry.require_verified(adjunct_trust, now_epoch_seconds); parse_accepted_adr(runtime_adr_raw, "ADR-0027", "runtime"); parse_accepted_adr(desktop_adr_raw, "ADR-0015", "desktop")
    except GovernanceStatusFailure as error: raise PolicyFailure("ADR_NOT_ACCEPTED") from error
    except Exception as error: raise PolicyFailure("REGISTRY_FRESHNESS_INVALID") from error
    payload = _payload(envelope); trust = _policy(rc0_policy); decision, decision_schema = _decision(shared_decision_raw)
    try: _envelope_now(loads_canonical(envelope.envelope_canonical_bytes), now_epoch_seconds)
    except PolicyFailure: raise
    except Exception as error: raise PolicyFailure("MAPPING_ENVELOPE_TIME_INVALID") from error
    _registry_schema(adjunct_trust, envelope, "gocode.rc0.platform-scope-mapping-policy/1", payload)
    claim, base, delta, composed = _lineage(adjunct_trust, claim_registry_raw, base_document_universe_raw, classified_delta_raw, composed_document_universe_raw)
    shared = _sha(canonical_bytes(decision) + b"\n")
    checks = {"shared_decision_payload_sha256": shared, "shared_decision_schema_sha256": decision_schema, "runtime_adr_document_sha256": _sha(runtime_adr_raw), "desktop_adr_document_sha256": _sha(desktop_adr_raw), "claim_migration_registry_payload_sha256": claim, "claim_migration_registry_schema_sha256": dict(adjunct_trust.adjunct_schema_digests)["gocode.v1-platform-scope-claim-migration/1"], "base_document_universe_payload_sha256": base, "classified_delta_payload_sha256": delta, "composed_document_universe_payload_sha256": composed, "adjunct_trust_registry_envelope_sha256": adjunct_trust.envelope_sha256, "adjunct_trust_registry_payload_sha256": adjunct_trust.payload_sha256}
    if payload.get("rc0_qualification_policy_digest") != trust.rc0_qualification_policy_digest: _fail("RC0_MAPPING_SET_MISMATCH")
    if _principal(envelope) != _registry(adjunct_trust, "mapping_policy_authority") or any(payload.get(key) != value for key, value in checks.items()) or len(owner_acceptances) != 2: _fail("MAPPING_BINDING_MISMATCH")
    owners: list[PrincipalBinding] = []
    for domain, adr, raw, role, item in (("runtime", "ADR-0027", runtime_adr_raw, "runtime_platform_owner", owner_acceptances[0]), ("desktop", "ADR-0015", desktop_adr_raw, "desktop_platform_owner", owner_acceptances[1])):
        body = _payload(item); _registry_schema(adjunct_trust, item, "gocode.governance.platform-decision-acceptance/1", body)
        try: _envelope_now(loads_canonical(item.envelope_canonical_bytes), now_epoch_seconds)
        except PolicyFailure: raise
        except Exception as error: raise PolicyFailure("OWNER_ACCEPTANCE_TIME_INVALID") from error
        if accepted_adr_digests(raw, adr, domain) != (shared, decision_schema) or _principal(item) != _registry(adjunct_trust, role) or body.get("owner_domain") != domain or body.get("adr_id") != adr or body.get("owner_subject_id") != item.issuer_subject_id or body.get("adr_document_sha256") != _sha(raw) or body.get("shared_decision_payload_sha256") != shared or body.get("shared_decision_schema_sha256") != decision_schema or payload.get(f"{domain}_owner_acceptance_envelope_sha256") != item.envelope_sha256: _fail("OWNER_ACCEPTANCE_MISMATCH")
        owners.append(_principal(item))
    principals = (_principal(envelope), *owners)
    if len({part for value in principals for part in (value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id)}) != 12: _fail("AUTHORITY_SEPARATION_MISMATCH")
    scopes, slots, profiles, pins, gates = _mapping_values(payload, trust, adjunct_trust)
    roles = tuple(AuthorityRoleBinding(role, (principal,)) for role, principal in adjunct_trust.role_principal_constraints)
    view = VerifiedMappingPolicy(_TOKEN, envelope_sha256=envelope.envelope_sha256, adjunct_trust_registry_envelope_sha256=adjunct_trust.envelope_sha256, adjunct_trust_registry_payload_sha256=adjunct_trust.payload_sha256, adjunct_trust=adjunct_trust, rc0_qualification_policy_digest=trust.rc0_qualification_policy_digest, shared_decision_payload_sha256=shared, claim_registry_payload_sha256=claim, base_document_universe_payload_sha256=base, classified_delta_payload_sha256=delta, composed_document_universe_payload_sha256=composed, activation_epoch=payload["activation_epoch"], platform_scopes=scopes, artifact_slots=slots, profile_states=profiles, host_identity_pins=pins, required_gate_ids=gates, rc0_trust_policy=trust, mapping_authority=_principal(envelope), governance_authorities=(owners[0], owners[1]), authority_roles=roles, adjunct_schema_digests=tuple(adjunct_trust.adjunct_schema_digests), _canonical_source_bytes=envelope.envelope_canonical_bytes)
    outer = loads_canonical(envelope.envelope_canonical_bytes)
    _STATES[view] = _MappingState(envelope.envelope_canonical_bytes, _view_digest(view), _trust_frame(outer), adjunct_trust)
    VerifiedMappingPolicy.require_verified(view, now_epoch_seconds)
    return view


def verify_mapping_policy(*args: object, **kwargs: object) -> None:
    """Reject the superseded G1 production mapping entrypoint before parsing."""
    _fail("SUPERSEDED_G1_UNSUPPORTED")
