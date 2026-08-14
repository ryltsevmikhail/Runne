"""Fixture-only transitive platform-qualified subject verifier."""
from __future__ import annotations

import hashlib
import weakref
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from scripts.rc0_policy.activation import ActivationView
from scripts.rc0_policy.adjunct_registry import VerifiedAdjunctTrustRegistry
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.composite_canonical import canonical_composite_bytes
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, PrincipalBinding, VerifiedEnvelope, require_fixture_verified
from scripts.rc0_policy.platform_attestation import PlatformAttestationView
from scripts.rc0_policy.platform_policy_mapping import AuthorityRoleBinding, VerifiedMappingPolicy
from scripts.rc0_policy.platform_policy_report import ReportArtifactBinding, VerifiedDeclaration, VerifiedReport


ROOT = Path(__file__).resolve().parents[2]
_TOKEN = object()
_SCHEMA = "gocode.rc0.platform-qualified-subject/1"
_SCHEMA_PATH = ROOT / "docs/schemas/rc0-platform-qualified-subject-v1.schema.json"
_SCOPES = (
    "linux-ubuntu-24_04-x86_64-production",
    "macos-14-arm64-development-preview",
    "windows-11-24h2-x86_64-production",
)


class SubjectFailure(ValueError):
    pass


def _fail(code: str) -> None: raise SubjectFailure(code)
def _sha(value: bytes) -> str: return hashlib.sha256(value).hexdigest()
def _principal(value: object) -> PrincipalBinding:
    if type(value) is not PrincipalBinding or any(type(part) is not str or not part for part in (value.role_id, value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id)): _fail("SUBJECT_PRINCIPAL_MISMATCH")
    return value
def _identity(value: VerifiedEnvelope) -> PrincipalBinding:
    if type(value) is not VerifiedEnvelope: _fail("SUBJECT_ENVELOPE_INVALID")
    actual = PrincipalBinding(value.issuer_role, value.issuer_subject_id, value.issuer_controlling_account_id, value.issuer_delegated_session_id, value.issuer_lane_id)
    if not _same_principal(_principal(value.trust.principal), actual): _fail("SUBJECT_PRINCIPAL_MISMATCH")
    return actual
def _same_principal(actual: object, expected: object) -> bool:
    if type(actual) is not PrincipalBinding or type(expected) is not PrincipalBinding: return False
    left = (actual.role_id, actual.subject_id, actual.controlling_account_id, actual.delegated_session_id, actual.lane_id)
    right = (expected.role_id, expected.subject_id, expected.controlling_account_id, expected.delegated_session_id, expected.lane_id)
    return all(type(item) is str for item in (*left, *right)) and left == right


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class QualifiedSubjectView:
    envelope_sha256: str; repository_id: str; issuer_identity: PrincipalBinding; rc0_qualified_declaration_envelope_sha256: str; rc0_verification_report_envelope_sha256: str; common_binding_group_payload_sha256: str; rc0_qualification_policy_digest: str; mapping_policy_envelope_sha256: str; active_activation_snapshot_envelope_sha256: str; normalized_mapping_payload_sha256: str; attestation_envelope_sha256s: tuple[str, str, str]; required_gate_set_payload_sha256: str; profile_state_set_payload_sha256: str; artifact_set_payload_sha256: str; _subject_envelope: VerifiedEnvelope; _declaration: VerifiedDeclaration; _report: VerifiedReport; _mapping: VerifiedMappingPolicy; _activation: ActivationView; _attestations: tuple[PlatformAttestationView, PlatformAttestationView, PlatformAttestationView]; _canonical_source_bytes: bytes; _verification_token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_verification_token"}: raise TypeError("QualifiedSubjectView is verifier-owned")
        for key, value in fields.items(): object.__setattr__(self, key, value)
        object.__setattr__(self, "_verification_token", token)
    def require_verified(self, now_epoch_seconds: int) -> None:
        state = _VIEWS.get(self)
        if type(self) is not QualifiedSubjectView or self._verification_token is not _TOKEN or state is None: _fail("SUBJECT_VERIFIED_INVALID")
        if not _same_private(self, state.inputs): _fail("SUBJECT_VERIFIED_INVALID")
        try: fields, source = _verify(*state.inputs, now_epoch_seconds)
        except Exception as error: raise SubjectFailure("SUBJECT_VERIFIED_INVALID") from error
        if not _same_public(self, state) or _fingerprint(fields, source) != state.fingerprint or _fingerprint(_public(self), self._canonical_source_bytes) != state.fingerprint or self._canonical_source_bytes != source:
            _fail("SUBJECT_VERIFIED_INVALID")


@dataclass(frozen=True)
class _State:
    inputs: tuple[object, ...]; public: tuple[object, ...]; source: bytes; fingerprint: str
_VIEWS: weakref.WeakKeyDictionary[QualifiedSubjectView, _State] = weakref.WeakKeyDictionary()


def _same_private(view: QualifiedSubjectView, inputs: tuple[object, ...]) -> bool:
    if len(inputs) != 6:
        return False
    subject, declaration, report, mapping, activation, attestations = inputs
    return (
        view._subject_envelope is subject and view._declaration is declaration
        and view._report is report and view._mapping is mapping
        and view._activation is activation and view._attestations is attestations
        and type(view._attestations) is tuple and len(view._attestations) == 3
        and all(current is expected for current, expected in zip(view._attestations, attestations))
        and type(view._canonical_source_bytes) is bytes
    )
def _same_public(view: QualifiedSubjectView, state: _State) -> bool:
    current = _public(view)
    return view._canonical_source_bytes is state.source and len(current) == len(state.public) and all(value is expected for value, expected in zip(current, state.public))


def _public(value: QualifiedSubjectView) -> tuple[object, ...]:
    names = tuple(name for name in value.__dataclass_fields__ if name not in {"_subject_envelope", "_declaration", "_report", "_mapping", "_activation", "_attestations", "_canonical_source_bytes", "_verification_token"})
    return tuple(getattr(value, name) for name in names)
def _fingerprint(fields: tuple[object, ...], source: bytes) -> str:
    return _sha(canonical_bytes({"fields": _serialize(fields), "source": _sha(source)}))
def _serialize(value: object) -> object:
    if type(value) in {str, int, bool} or value is None: return value
    if type(value) is tuple: return [_serialize(item) for item in value]
    if type(value) is PrincipalBinding: return [value.role_id, value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id]
    _fail("SUBJECT_VERIFIED_INVALID")


def _require_inputs(activation: object, attestations: object, mapping: object, declaration: object, report: object, now: int) -> tuple[PlatformAttestationView, PlatformAttestationView, PlatformAttestationView]:
    if type(now) is not int or isinstance(now, bool) or type(activation) is not ActivationView or type(mapping) is not VerifiedMappingPolicy or type(attestations) not in (tuple, list) or len(attestations) != 3: _fail("SUBJECT_INPUT_INVALID")
    try: activation.require_verified(now)
    except Exception as error: raise SubjectFailure("ACTIVATION_VERIFIED_INVALID") from error
    if activation.state != "active" or activation.runner_consumer_identity is None or activation.downstream_consumer_identity is None: _fail("ACTIVATION_INACTIVE")
    values = tuple(attestations)
    if any(type(item) is not PlatformAttestationView for item in values): _fail("SUBJECT_INPUT_INVALID")
    for item in values:
        try: item.require_verified(now)
        except Exception as error: raise SubjectFailure("ATTESTATION_VERIFIED_INVALID") from error
        try: item.require_dependencies(mapping, mapping.adjunct_trust, activation, declaration, report, now)
        except Exception as error: raise SubjectFailure("ATTESTATION_DEPENDENCY_INVALID") from error
    return values  # type: ignore[return-value]


def _roles(mapping: VerifiedMappingPolicy, activation: ActivationView, declaration: VerifiedDeclaration, report: VerifiedReport, attestations: tuple[PlatformAttestationView, ...], now: int) -> tuple[AuthorityRoleBinding, ...]:
    registry = mapping.adjunct_trust
    if type(registry) is not VerifiedAdjunctTrustRegistry: _fail("SUBJECT_ROLE_MISMATCH")
    try: registry.require_verified(now)
    except Exception as error: raise SubjectFailure("SUBJECT_ROLE_MISMATCH") from error
    rows = registry.role_principal_constraints
    if type(rows) is not tuple or len(rows) != 14 or tuple(role for role, _ in rows) != tuple(sorted(role for role, _ in rows)): _fail("SUBJECT_ROLE_MISMATCH")
    expected = dict(rows)
    if any(type(role) is not str or type(value) is not PrincipalBinding for role, value in rows): _fail("SUBJECT_ROLE_MISMATCH")
    signed = {
        "mapping_policy_authority": mapping.mapping_authority,
        "runtime_platform_owner": mapping.governance_authorities[0],
        "desktop_platform_owner": mapping.governance_authorities[1],
        "rc0_qualification_reporter": report.reporter_identity,
        "rc0_qualification_declarer": declaration.declarer_identity,
        "policy_authority": activation.policy_authority_identity,
    }
    for attestation in attestations:
        signed["qualification_aggregator"] = attestation.attestation_issuer_identity
        signed["native_host_attestor"] = attestation.host.host_attestor_identity
        for closure in attestation.closures:
            signed["artifact_classifier_a"], signed["artifact_classifier_b"] = closure.classifier_identities
        for row in attestation.profile_rows: signed[row.evidence_identity.role_id] = row.evidence_identity
    if any(role not in expected or not _same_principal(_principal(value), expected[role]) for role, value in signed.items()): _fail("SUBJECT_ROLE_MISMATCH")
    principals = tuple(expected[role] for role, _ in rows)
    for dimension in ("subject_id", "controlling_account_id", "delegated_session_id", "lane_id"):
        values = tuple(getattr(value, dimension) for value in principals)
        if len(set(values)) != len(values): _fail("SUBJECT_PRINCIPAL_OVERLAP")
    return tuple(AuthorityRoleBinding(role, (principal,)) for role, principal in rows)


def fixture_collect_authority_roles(subject: VerifiedEnvelope, declaration: VerifiedDeclaration, report: VerifiedReport, mapping: VerifiedMappingPolicy, activation: ActivationView, attestations: Sequence[PlatformAttestationView], now_epoch_seconds: int) -> Sequence[AuthorityRoleBinding]:
    _verify(subject, declaration, report, mapping, activation, attestations, now_epoch_seconds)
    values = tuple(attestations)
    return _roles(mapping, activation, declaration, report, values, now_epoch_seconds)


def _profile_digest(attestations: tuple[PlatformAttestationView, ...]) -> str:
    rows = []
    for item in attestations:
        for row in item.profile_rows:
            if type(row.profile_id) is not str or type(row.profile_revision) not in {int, str} or type(row.profile_sha256) not in {str, type(None)} or type(row.state) is not str or type(row.evidence_envelope_sha256) is not str: _fail("PROFILE_STATE_MISMATCH")
            rows.append([item.platform_scope_id, row.profile_id, row.profile_revision, row.profile_sha256, row.state, row.evidence_envelope_sha256])
    rows.sort(key=canonical_bytes)
    if len({canonical_bytes(row) for row in rows}) != len(rows): _fail("PROFILE_STATE_MISMATCH")
    return _sha(canonical_bytes(rows))
def _artifact_order_key(row: tuple[str, str, int, str]) -> tuple[bytes, bytes, bytes, bytes]:
    return (row[0].encode(), row[1].encode(), str(row[2]).encode(), row[3].encode())
def _artifacts(attestations: tuple[PlatformAttestationView, ...], report: VerifiedReport) -> None:
    actual = []
    for item in attestations:
        for row in item.closures:
            value = (row.relative_path, row.artifact_sha256, row.size, row.locator)
            if type(value[0]) is not str or type(value[1]) is not str or type(value[2]) is not int or isinstance(value[2], bool) or type(value[3]) is not str: _fail("ARTIFACT_SET_MISMATCH")
            actual.append(value)
    if len({canonical_bytes(list(row)) for row in actual}) != len(actual): _fail("ARTIFACT_SET_MISMATCH")
    expected = tuple((row.relative_path, row.sha256, row.size, row.locator) for row in report.artifact_bindings)
    if any(type(row) is not ReportArtifactBinding for row in report.artifact_bindings) or tuple(sorted(actual, key=_artifact_order_key)) != expected: _fail("ARTIFACT_SET_MISMATCH")
def _mapping_digest(attestations: tuple[PlatformAttestationView, ...]) -> str:
    from scripts.rc0_policy.platform_matrix import normalized_platform_mapping_payload
    return _sha(normalized_platform_mapping_payload(attestations))
def _source(subject: VerifiedEnvelope, declaration: VerifiedDeclaration, report: VerifiedReport, mapping: VerifiedMappingPolicy, activation: ActivationView, attestations: tuple[PlatformAttestationView, ...]) -> bytes:
    try:
        return canonical_composite_bytes({"subject": loads_canonical(subject.envelope_canonical_bytes), "declaration": loads_canonical(declaration._canonical_declaration_envelope_bytes), "report": loads_canonical(report._canonical_report_envelope_bytes), "mapping": loads_canonical(mapping._canonical_source_bytes), "activation": loads_canonical(activation._canonical_source_bytes), "attestations": [{"envelope_sha256": item.envelope_sha256, "source_sha256": _sha(item._canonical_source_bytes)} for item in attestations]})
    except Exception as error: raise SubjectFailure("SUBJECT_SOURCE_INVALID") from error


def _verify(subject: VerifiedEnvelope, declaration: VerifiedDeclaration, report: VerifiedReport, mapping: VerifiedMappingPolicy, activation: ActivationView, attestations: Sequence[PlatformAttestationView], now: int) -> tuple[tuple[object, ...], bytes]:
    values = _require_inputs(activation, attestations, mapping, declaration, report, now)
    try: mapping.require_verified(now); declaration.require_dependencies(mapping, report, now); report.require_dependencies(mapping, now); activation.require_dependencies(mapping, mapping.adjunct_trust, now); require_fixture_verified(subject)
    except Exception as error: raise SubjectFailure("SUBJECT_DEPENDENCY_INVALID") from error
    _roles(mapping, activation, declaration, report, values, now)
    registry = mapping.adjunct_trust; raw = _SCHEMA_PATH.read_bytes(); identity = _identity(subject)
    try: payload = loads_canonical(subject.payload_canonical_bytes); AdjunctSchemaStore({_SCHEMA: raw}).validate(_SCHEMA, subject.payload_schema_sha256, payload)
    except Exception as error: raise SubjectFailure("SUBJECT_ENVELOPE_INVALID") from error
    expected_issuer = dict(registry.role_principal_constraints).get("qualification_aggregator")
    if subject.payload_schema_id != _SCHEMA or subject.payload_schema_sha256 != dict(registry.adjunct_schema_digests).get(_SCHEMA) or _sha(raw) != subject.payload_schema_sha256 or not _same_principal(identity, expected_issuer) or subject.payload_sha256 != _sha(subject.payload_canonical_bytes) or not subject.not_before_epoch_seconds <= subject.issued_at_epoch_seconds <= now <= subject.expires_at_epoch_seconds: _fail("SUBJECT_ENVELOPE_INVALID")
    hashes = tuple(sorted(item.envelope_sha256 for item in values))
    if tuple(item.platform_scope_id for item in sorted(values, key=lambda item: item.platform_scope_id)) != _SCOPES or len(set(hashes)) != 3: _fail("ATTESTATION_SET_MISMATCH")
    expected = {"repository_id": "gocode", "rc0_qualified_declaration_envelope_sha256": declaration.envelope_sha256, "rc0_verification_report_envelope_sha256": report.envelope_sha256, "common_binding_group_payload_sha256": declaration.common_binding_group_payload_sha256, "rc0_qualification_policy_digest": declaration.rc0_qualification_policy_digest, "mapping_policy_envelope_sha256": mapping.envelope_sha256, "active_activation_snapshot_envelope_sha256": activation.snapshot_envelope_sha256, "platform_attestation_envelope_sha256s": list(hashes), "normalized_platform_mapping_payload_sha256": _mapping_digest(values), "required_gate_set_payload_sha256": declaration.required_gate_set_payload_sha256, "profile_state_set_payload_sha256": _profile_digest(values), "artifact_set_payload_sha256": declaration.artifact_set_payload_sha256}
    if any(payload.get(key) != value for key, value in expected.items()) or declaration.report is not report or declaration.verification_report_envelope_sha256 != report.envelope_sha256 or report.rc0_qualification_policy_digest != mapping.rc0_qualification_policy_digest or declaration.artifact_set_payload_sha256 != report.artifact_set_payload_sha256 or declaration.required_gate_set_payload_sha256 != report.required_gate_set_payload_sha256: _fail("SUBJECT_BINDING_MISMATCH")
    _artifacts(values, report)
    fields = (subject.envelope_sha256, payload["repository_id"], identity, payload["rc0_qualified_declaration_envelope_sha256"], payload["rc0_verification_report_envelope_sha256"], payload["common_binding_group_payload_sha256"], payload["rc0_qualification_policy_digest"], payload["mapping_policy_envelope_sha256"], payload["active_activation_snapshot_envelope_sha256"], payload["normalized_platform_mapping_payload_sha256"], hashes, payload["required_gate_set_payload_sha256"], payload["profile_state_set_payload_sha256"], payload["artifact_set_payload_sha256"])
    return fields, _source(subject, declaration, report, mapping, activation, values)


def fixture_verify_qualified_subject(subject: VerifiedEnvelope, declaration: VerifiedDeclaration, report: VerifiedReport, mapping: VerifiedMappingPolicy, activation: ActivationView, attestations: Sequence[PlatformAttestationView], now_epoch_seconds: int) -> QualifiedSubjectView:
    inputs = (subject, declaration, report, mapping, activation, tuple(attestations))
    fields, source = _verify(*inputs, now_epoch_seconds)
    names = tuple(name for name in QualifiedSubjectView.__dataclass_fields__ if name not in {"_subject_envelope", "_declaration", "_report", "_mapping", "_activation", "_attestations", "_canonical_source_bytes", "_verification_token"})
    view = QualifiedSubjectView(_TOKEN, **dict(zip(names, fields)), _subject_envelope=subject, _declaration=declaration, _report=report, _mapping=mapping, _activation=activation, _attestations=tuple(inputs[-1]), _canonical_source_bytes=source)
    _VIEWS[view] = _State(inputs, _public(view), source, _fingerprint(fields, source)); view.require_verified(now_epoch_seconds)
    return view


def collect_authority_roles(*args: object, **kwargs: object) -> None:
    """Reject the superseded G1 production role entrypoint before parsing."""
    _fail("SUPERSEDED_G1_UNSUPPORTED")


def verify_qualified_subject(*args: object, **kwargs: object) -> None:
    """Reject the superseded G1 production subject entrypoint before parsing."""
    _fail("SUPERSEDED_G1_UNSUPPORTED")
