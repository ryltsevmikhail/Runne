"""Pure post-trust profile, host-control, and artifact-shape semantics."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from scripts.rc0_policy.external_envelope import PrincipalBinding
from scripts.rc0_policy.platform_policy_mapping import (
    ArtifactSlotPolicyRow, HostPolicyRow, PlatformScopePolicyRow,
    ProfileStatePolicyRow, Rc0TrustPolicyView, VerifiedMappingPolicy,
)
from scripts.rc0_policy.platform_policy_report import RequiredGateResultRow, VerifiedReport


_CONTROLS = {
    "Ubuntu": frozenset(("linux_protected_transport", "linux_landlock", "linux_seccomp", "linux_cgroups_v2", "linux_descendant_cleanup", "linux_direct_egress_denial")),
    "Windows": frozenset(("windows_owner_acl", "windows_owner_dacl", "windows_reparse_safe", "windows_appcontainer", "windows_job_object_cleanup", "windows_descendant_cleanup", "windows_direct_egress_denial")),
    "macOS": frozenset(("macos_protected_transport", "macos_cleanup", "macos_direct_egress_denial", "macos_no_login_keychain", "macos_no_ssh_material", "macos_no_workspace", "macos_no_credential_environment", "macos_no_inherited_handles")),
}
_ALL_CONTROLS = frozenset().union(*_CONTROLS.values())
_COMMON_SHAPES = frozenset(("path_normalization", "traversal", "symlink", "hardlink", "special_file", "case_collision", "unlisted_package_script"))
_SLOT_SHAPES = {
    "linux-appimage": "linux_product_payload", "linux-deb": "linux_product_payload",
    "windows-installer-unsigned": "windows_helper",
    "macos-app-development-adhoc": "macos_app_dmg", "macos-dmg-development-adhoc": "macos_app_dmg",
}
_SHAPES = _COMMON_SHAPES | frozenset(("linux_product_payload", "windows_helper", "macos_app_dmg"))
_CANONICAL_RESULTS = {
    "required": "PASS", "external_canary_only": "PASS",
    "disabled_by_policy": "DISABLED_BY_POLICY", "backend_unavailable": "BackendUnavailable",
}


@dataclass(frozen=True)
class HostControlResult:
    control_id: str
    result: Literal["PASS", "FAILED", "NOT_APPLICABLE"]


@dataclass(frozen=True)
class AttestationGateBinding:
    repository_id: str
    mapping_policy_envelope_sha256: str
    active_activation_snapshot_envelope_sha256: str
    common_binding_group_payload_sha256: str
    platform_scope_id: str


@dataclass(frozen=True)
class AttestationGateFailure:
    gate_id: str
    stage: Literal["PRODUCTION_QUALIFICATION"]
    execution_outcome: Literal["FAIL", "NOT_RUN"]
    gate_result: Literal["BLOCKED"]
    blocked_reason: Literal["REQUIRED_GATE_FAILED", "REQUIRED_GATE_NOT_RUN"]
    binding: AttestationGateBinding


class AttestationFailure(ValueError):
    """A semantic mismatch; only post-trust failures carry a gate result."""

    def __init__(self, code: str, gate_failure: AttestationGateFailure | None = None) -> None:
        self.code, self.gate_failure = code, gate_failure
        super().__init__(code)


@dataclass(frozen=True)
class ProfileRow:
    profile_id: str
    profile_revision: int | str
    profile_sha256: str | None
    state: str
    canonical_result: Literal["PASS", "DISABLED_BY_POLICY", "BackendUnavailable"]
    artifact_slot_ids: tuple[str, ...]
    rc0_gate_evidence_sha256s: tuple[str, ...]
    evidence_envelope_sha256: str
    evidence_identity: PrincipalBinding


@dataclass(frozen=True)
class AuthenticatedProfileEvidence:
    """A parsed, authenticated profile or canary payload with its envelope identity."""

    payload: Mapping[str, object]
    evidence_envelope_sha256: str
    evidence_identity: PrincipalBinding


def _mismatch(code: str) -> None:
    raise AttestationFailure(code)


def _fields(value: object, names: tuple[str, ...]) -> bool:
    return set(getattr(value, "__dict__", ())) == set(names)


def _binding(value: object) -> AttestationGateBinding:
    if type(value) is not AttestationGateBinding or not _fields(value, ("repository_id", "mapping_policy_envelope_sha256", "active_activation_snapshot_envelope_sha256", "common_binding_group_payload_sha256", "platform_scope_id")) or any(type(item) is not str or not item for item in value.__dict__.values()):
        _mismatch("ATTESTATION_GATE_BINDING_MISMATCH")
    return value


def _principal(value: object) -> PrincipalBinding:
    if type(value) is not PrincipalBinding or not _fields(value, ("role_id", "subject_id", "controlling_account_id", "delegated_session_id", "lane_id")) or any(type(item) is not str or not item for item in value.__dict__.values()):
        _mismatch("PROFILE_MISMATCH")
    return value


def _record(value: object, kind: type[object], names: tuple[str, ...]) -> bool:
    return type(value) is kind and _fields(value, names) and all(type(getattr(value, name)) is str for name in names)


def _mapping(value: object) -> VerifiedMappingPolicy:
    if type(value) is not VerifiedMappingPolicy or type(value.envelope_sha256) is not str or type(value.required_gate_ids) is not tuple or type(value.rc0_trust_policy) is not Rc0TrustPolicyView or any(type(getattr(value, name)) is not tuple for name in ("platform_scopes", "artifact_slots", "profile_states", "host_identity_pins")):
        _mismatch("ATTESTATION_GATE_MAPPING_MISMATCH")
    if not value.required_gate_ids or tuple(sorted(value.required_gate_ids)) != value.required_gate_ids or len(set(value.required_gate_ids)) != len(value.required_gate_ids) or any(type(item) is not str or not item for item in value.required_gate_ids):
        _mismatch("ATTESTATION_GATE_MAPPING_MISMATCH")
    scopes, slots, profiles, pins, trust = value.platform_scopes, value.artifact_slots, value.profile_states, value.host_identity_pins, value.rc0_trust_policy
    if not all((_record(row, PlatformScopePolicyRow, ("platform_scope_id", "qualification_class", "support_disposition", "os_family", "os_version", "architecture")) for row in scopes)) or not all((_record(row, ArtifactSlotPolicyRow, ("platform_scope_id", "artifact_slot_id", "artifact_kind")) for row in slots)) or not all((_record(row, HostPolicyRow, ("platform_scope_id", "os_build", "kernel_or_image_sha256", "backend_id", "backend_version", "probe_set_payload_sha256", "enforcement_descriptor_payload_sha256")) for row in pins)):
        _mismatch("ATTESTATION_GATE_MAPPING_MISMATCH")
    if not all(type(row) is ProfileStatePolicyRow and _fields(row, ("platform_scope_id", "profile_id", "profile_revision", "profile_sha256", "state")) and type(row.platform_scope_id) is str and type(row.profile_id) is str and type(row.profile_revision) in (int, str) and type(row.profile_sha256) in (str, type(None)) and type(row.state) is str for row in profiles):
        _mismatch("ATTESTATION_GATE_MAPPING_MISMATCH")
    if not _fields(trust, ("rc0_qualification_policy_digest", "canonical_bytes", "canonical_sha256", "schema_id_hash_pairs", "required_gate_projection", "legacy_issuer_role_strings")) or type(trust.rc0_qualification_policy_digest) is not str or type(trust.canonical_bytes) is not bytes or type(trust.canonical_sha256) is not str or type(trust.schema_id_hash_pairs) is not tuple or type(trust.required_gate_projection) is not tuple or type(trust.legacy_issuer_role_strings) is not tuple or any(type(row) is not tuple or len(row) != 2 or any(type(item) is not str for item in row) for row in trust.schema_id_hash_pairs) or any(type(row) is not tuple or len(row) != 5 or any(type(item) is not str for item in row) for row in trust.required_gate_projection) or any(type(item) is not str for item in trust.legacy_issuer_role_strings):
        _mismatch("ATTESTATION_GATE_MAPPING_MISMATCH")
    return value


def _bound_scope(binding: AttestationGateBinding, mapping: VerifiedMappingPolicy) -> PlatformScopePolicyRow:
    binding, mapping = _binding(binding), _mapping(mapping)
    if binding.mapping_policy_envelope_sha256 != mapping.envelope_sha256:
        _mismatch("ATTESTATION_GATE_BINDING_MISMATCH")
    scopes = tuple(row for row in mapping.platform_scopes if row.platform_scope_id == binding.platform_scope_id)
    if len(scopes) != 1:
        _mismatch("ATTESTATION_GATE_BINDING_MISMATCH")
    return scopes[0]


def _production_gate(mapping: VerifiedMappingPolicy) -> str:
    mapping = _mapping(mapping)
    rows = mapping.rc0_trust_policy.required_gate_projection
    if type(rows) is not tuple or any(type(row) is not tuple or len(row) != 5 or any(type(item) is not str for item in row) for row in rows):
        _mismatch("ATTESTATION_GATE_MAPPING_MISMATCH")
    if tuple(sorted(row[0] for row in rows)) != mapping.required_gate_ids:
        _mismatch("ATTESTATION_GATE_MAPPING_MISMATCH")
    production = tuple(row[0] for row in rows if row[1] == "PRODUCTION_QUALIFICATION")
    if len(production) != 1:
        _mismatch("ATTESTATION_GATE_MAPPING_MISMATCH")
    return production[0]


def gate_failure(binding: AttestationGateBinding, mapping: VerifiedMappingPolicy, category: str, item_id: str, result: str) -> AttestationGateFailure:
    """Return the one permitted normalized result for an authenticated failure."""
    binding, mapping = _binding(binding), _mapping(mapping)
    _bound_scope(binding, mapping)
    if type(category) is not str or type(item_id) is not str or type(result) is not str or result not in {"FAILED", "NOT_APPLICABLE"}:
        _mismatch("ATTESTATION_GATE_RESULT_INVALID")
    outcome, reason = (("FAIL", "REQUIRED_GATE_FAILED") if result == "FAILED" else ("NOT_RUN", "REQUIRED_GATE_NOT_RUN"))
    return AttestationGateFailure(_production_gate(mapping), "PRODUCTION_QUALIFICATION", outcome, "BLOCKED", reason, binding)


def _post_trust(binding: AttestationGateBinding, mapping: VerifiedMappingPolicy, category: str, item_id: str, result: str) -> None:
    failure = gate_failure(binding, mapping, category, item_id, result)
    raise AttestationFailure(f"ATTESTATION_{category.upper()}_{result}:{item_id}", failure)


def verify_host_controls(rows: Sequence[Mapping[str, object]], os_family: str, binding: AttestationGateBinding, mapping: VerifiedMappingPolicy) -> tuple[HostControlResult, ...]:
    """Require the closed, sorted 21-control platform-applicability matrix."""
    binding, mapping = _binding(binding), _mapping(mapping)
    scope = _bound_scope(binding, mapping)
    applicable = _CONTROLS.get(os_family) if type(os_family) is str else None
    if applicable is None or os_family != scope.os_family or type(rows) not in (tuple, list) or len(rows) != len(_ALL_CONTROLS):
        _mismatch("HOST_CONTROL_MISMATCH")
    parsed: list[HostControlResult] = []
    for row in rows:
        if type(row) is not dict or any(type(key) is not str for key in row) or set(row) != {"control_id", "result"}:
            _mismatch("HOST_CONTROL_MISMATCH")
        control_id, result = row.get("control_id"), row.get("result")
        if type(control_id) is not str or type(result) is not str or result not in {"PASS", "FAILED", "NOT_APPLICABLE"}:
            _mismatch("HOST_CONTROL_MISMATCH")
        parsed.append(HostControlResult(control_id, result))
    if tuple(row.control_id for row in parsed) != tuple(sorted(_ALL_CONTROLS)) or {row.control_id for row in parsed} != _ALL_CONTROLS:
        _mismatch("HOST_CONTROL_MISMATCH")
    for row in parsed:
        if row.control_id not in applicable:
            if row.result != "NOT_APPLICABLE": _mismatch("HOST_CONTROL_MISMATCH")
        elif row.result != "PASS":
            _post_trust(binding, mapping, "control", row.control_id, row.result)
    return tuple(parsed)


def verify_host_policy(host: Mapping[str, object], mapping: VerifiedMappingPolicy, scope_id: str, binding: AttestationGateBinding) -> tuple[HostControlResult, ...]:
    """Compare an already authenticated host projection to mapping identity pins."""
    mapping = _mapping(mapping)
    if type(host) is not dict or any(type(key) is not str for key in host) or type(scope_id) is not str:
        _mismatch("HOST_POLICY_MISMATCH")
    scope = next((row for row in mapping.platform_scopes if row.platform_scope_id == scope_id), None)
    pin = next((row for row in mapping.host_identity_pins if row.platform_scope_id == scope_id), None)
    if type(scope) is not PlatformScopePolicyRow or not _fields(scope, ("platform_scope_id", "qualification_class", "support_disposition", "os_family", "os_version", "architecture")) or type(pin) is not HostPolicyRow or not _fields(pin, ("platform_scope_id", "os_build", "kernel_or_image_sha256", "backend_id", "backend_version", "probe_set_payload_sha256", "enforcement_descriptor_payload_sha256")) or any(type(value) is not str for value in (scope.os_family, scope.os_version, scope.architecture, pin.os_build, pin.kernel_or_image_sha256, pin.backend_id, pin.backend_version, pin.probe_set_payload_sha256, pin.enforcement_descriptor_payload_sha256)) or any(type(host.get(name)) is not str or host[name] != expected for name, expected in (("platform_scope_id", scope_id), ("os_family", scope.os_family), ("os_version", scope.os_version), ("architecture", scope.architecture), ("native_mode", "native"), ("os_build", pin.os_build), ("kernel_or_image_sha256", pin.kernel_or_image_sha256), ("backend_id", pin.backend_id), ("backend_version", pin.backend_version), ("probe_set_payload_sha256", pin.probe_set_payload_sha256), ("enforcement_descriptor_payload_sha256", pin.enforcement_descriptor_payload_sha256))):
        _mismatch("HOST_POLICY_MISMATCH")
    return verify_host_controls(host.get("control_results"), scope.os_family, binding, mapping)


def verify_shape_results(shape_results: Mapping[str, object], artifact_slot_id: str, binding: AttestationGateBinding, mapping: VerifiedMappingPolicy) -> None:
    """Check authenticated manifest results without parsing an artifact package."""
    binding, mapping = _binding(binding), _mapping(mapping)
    scope = _bound_scope(binding, mapping)
    applicable = _SLOT_SHAPES.get(artifact_slot_id) if type(artifact_slot_id) is str else None
    slots = tuple(row for row in mapping.artifact_slots if row.artifact_slot_id == artifact_slot_id)
    if applicable is None or len(slots) != 1 or slots[0].platform_scope_id != scope.platform_scope_id or type(shape_results) is not dict or any(type(key) is not str for key in shape_results) or set(shape_results) != _SHAPES:
        _mismatch("ARTIFACT_SHAPE_MISMATCH")
    for shape_id in sorted(_SHAPES):
        result = shape_results[shape_id]
        expected = "PASS" if shape_id in _COMMON_SHAPES or shape_id == applicable else "NOT_APPLICABLE"
        if type(result) is not str or result not in {"PASS", "FAILED", "NOT_APPLICABLE"}:
            _mismatch("ARTIFACT_SHAPE_MISMATCH")
        if result != expected:
            if expected == "PASS" and result in {"FAILED", "NOT_APPLICABLE"}:
                _post_trust(binding, mapping, "shape", shape_id, result)
            _mismatch("ARTIFACT_SHAPE_MISMATCH")


def _profile_gates(report: VerifiedReport) -> tuple[str, ...]:
    if type(report) is not VerifiedReport:
        _mismatch("PROFILE_GATE_EVIDENCE_MISMATCH")
    try:
        rows = report.required_gate_results
        if type(rows) is not tuple or any(type(row) is not RequiredGateResultRow or not _fields(row, ("gate_id", "stage", "execution_outcome", "gate_result", "blocked_reason", "canonical_row_bytes")) or type(row.gate_id) is not str or type(row.stage) is not str or type(row.execution_outcome) is not str or type(row.gate_result) is not str or type(row.blocked_reason) not in (str, type(None)) or type(row.canonical_row_bytes) is not bytes for row in rows):
            _mismatch("PROFILE_GATE_EVIDENCE_MISMATCH")
        values = tuple(sorted(hashlib.sha256(b"gocode.rc0.profile-gate-evidence-row/1\0" + row.canonical_row_bytes).hexdigest() for row in rows))
    except Exception as error:
        raise AttestationFailure("PROFILE_GATE_EVIDENCE_MISMATCH") from error
    if len(set(values)) != len(values): _mismatch("PROFILE_GATE_EVIDENCE_MISMATCH")
    return values


def verify_profile_rows(profiles: Sequence[AuthenticatedProfileEvidence], canaries: Sequence[AuthenticatedProfileEvidence], mapping: VerifiedMappingPolicy, report: VerifiedReport, scope_id: str) -> tuple[ProfileRow, ...]:
    """Require the exact mapping-selected profiles, slots, gates and macOS canary."""
    mapping = _mapping(mapping)
    if type(profiles) not in (tuple, list) or type(canaries) not in (tuple, list) or type(scope_id) is not str:
        _mismatch("PROFILE_MISMATCH")
    expected = tuple(row for row in mapping.profile_states if row.platform_scope_id == scope_id)
    slots = tuple(sorted(row.artifact_slot_id for row in mapping.artifact_slots if row.platform_scope_id == scope_id))
    gates = _profile_gates(report)
    if not expected or not slots or any(type(row) is not ProfileStatePolicyRow or not _fields(row, ("platform_scope_id", "profile_id", "profile_revision", "profile_sha256", "state")) or type(row.platform_scope_id) is not str or type(row.profile_id) is not str or type(row.profile_revision) not in (int, str) or type(row.profile_sha256) not in (str, type(None)) or type(row.state) is not str for row in expected) or any(type(row) is not ArtifactSlotPolicyRow or not _fields(row, ("platform_scope_id", "artifact_slot_id", "artifact_kind")) or type(row.platform_scope_id) is not str or type(row.artifact_slot_id) is not str or type(row.artifact_kind) is not str for row in mapping.artifact_slots):
        _mismatch("PROFILE_MISMATCH")
    entries = ((False, profiles), (True, canaries))
    actual: dict[str, tuple[bool, AuthenticatedProfileEvidence]] = {}
    for is_canary, sequence in entries:
        for item in sequence:
            if type(item) is not AuthenticatedProfileEvidence or not _fields(item, ("payload", "evidence_envelope_sha256", "evidence_identity")) or type(item.payload) is not dict or any(type(key) is not str for key in item.payload) or type(item.evidence_envelope_sha256) is not str or not item.evidence_envelope_sha256:
                _mismatch("PROFILE_MISMATCH")
            _principal(item.evidence_identity)
            profile_id = item.payload.get("profile_id")
            if type(profile_id) is not str or profile_id in actual:
                _mismatch("PROFILE_MISMATCH")
            actual[profile_id] = (is_canary, item)
    if set(actual) != {row.profile_id for row in expected} or len(actual) != len(expected):
        _mismatch("PROFILE_MISMATCH")
    rows: list[ProfileRow] = []
    for policy in expected:
        is_canary, item = actual[policy.profile_id]
        payload = item.payload
        wants_canary = policy.state == "external_canary_only"
        if is_canary != wants_canary or (wants_canary and scope_id != "macos-14-arm64-development-preview"):
            _mismatch("PROFILE_CANARY_MISMATCH")
        expected_result = _CANONICAL_RESULTS.get(policy.state)
        if expected_result is None or type(policy.profile_revision) not in (int, str) or type(policy.profile_sha256) not in (str, type(None)) or any(type(payload.get(name)) is not type(wanted) or payload[name] != wanted for name, wanted in (("platform_scope_id", scope_id), ("profile_id", policy.profile_id), ("profile_revision", policy.profile_revision), ("profile_sha256", policy.profile_sha256), ("state", policy.state), ("canonical_result", expected_result))):
            _mismatch("PROFILE_MISMATCH")
        artifact_slot_ids, gate_digests = payload.get("artifact_slot_ids"), payload.get("rc0_gate_evidence_sha256s")
        if type(artifact_slot_ids) is not list or type(gate_digests) is not list or any(type(value) is not str for value in artifact_slot_ids) or any(type(value) is not str for value in gate_digests) or tuple(artifact_slot_ids) != slots or tuple(gate_digests) != gates:
            _mismatch("PROFILE_MISMATCH")
        if wants_canary and (type(payload.get("operator_lane_id")) is not str or payload["operator_lane_id"] != item.evidence_identity.lane_id):
            _mismatch("PROFILE_CANARY_MISMATCH")
        rows.append(ProfileRow(policy.profile_id, policy.profile_revision, policy.profile_sha256, policy.state, expected_result, slots, gates, item.evidence_envelope_sha256, item.evidence_identity))
    return tuple(rows)
