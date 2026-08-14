"""Opaque authenticated platform-scope attestation verifier."""
from __future__ import annotations

import hashlib
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from scripts.rc0_policy.activation import ActivationView
from scripts.rc0_policy.adjunct_registry import VerifiedAdjunctTrustRegistry
from scripts.rc0_policy.artifact_closure import ArtifactClosure, ArtifactClosureFailure, verify_artifact_closure
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.composite_canonical import canonical_composite_bytes, loads_composite_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, PrincipalBinding, VerifiedEnvelope, require_fixture_verified, timestamp_epoch_seconds
from scripts.rc0_policy.platform_attestation_evidence import AttestationEvidenceBundle, HostIdentity, digests, evidence_record, groups, host, principal, profiles, source
from scripts.rc0_policy.platform_attestation_profiles import AttestationFailure, AttestationGateBinding, HostControlResult, ProfileRow, verify_host_policy, verify_profile_rows, verify_shape_results
from scripts.rc0_policy.platform_policy_mapping import VerifiedMappingPolicy
from scripts.rc0_policy.platform_policy_report import VerifiedDeclaration, VerifiedReport, report_common_binding_group

ROOT = Path(__file__).resolve().parents[2]; _TOKEN = object(); ATTESTATION = "gocode.rc0.platform-scope-attestation/1"
CATEGORIES = (("artifact_measurements", "gocode.rc0.artifact-measurement-record/1"), ("host_evidence_records", "gocode.rc0.native-host-evidence-record/1"), ("profile_evidence_records", "gocode.rc0.profile-evidence-record/1"), ("canary_evidence_records", "gocode.rc0.canary-evidence-record/1"))
def _fail(code: str) -> None: raise AttestationFailure(code)
def _sha(value: bytes) -> str: return hashlib.sha256(value).hexdigest()

@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class PlatformAttestationView:
    envelope_sha256: str; repository_id: str; attestation_issuer_identity: PrincipalBinding; mapping_policy_envelope_sha256: str; rc0_qualification_policy_digest: str; active_activation_snapshot_envelope_sha256: str; common_binding_group_payload_sha256: str; platform_scope_id: str; qualification_class: str; support_disposition: str; host: HostIdentity; closures: tuple[ArtifactClosure, ...]; profile_rows: tuple[ProfileRow, ...]; evidence_envelope_sha256s: tuple[str, ...]; evidence_identities: tuple[PrincipalBinding, ...]; _canonical_source_bytes: bytes; _verification_token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **values: object) -> None:
        if token is not _TOKEN or set(values) != set(self.__dataclass_fields__) - {"_verification_token"}: raise TypeError("PlatformAttestationView is verifier-owned")
        for key, value in values.items(): object.__setattr__(self, key, value)
        object.__setattr__(self, "_verification_token", token)
    def require_verified(self, now_epoch_seconds: int) -> None:
        state = _VIEWS.get(self)
        if type(self) is not PlatformAttestationView or self._verification_token is not _TOKEN or state is None: _fail("ATTESTATION_VERIFIED_INVALID")
        self._require_current_integrity()
        try: fields, raw = _verify(*state.inputs, now_epoch_seconds)
        except Exception as error: raise AttestationFailure("ATTESTATION_VERIFIED_INVALID") from error
        if _fingerprint(fields, raw) != state.fingerprint: _fail("ATTESTATION_VERIFIED_INVALID")
    def _require_current_integrity(self) -> None:
        state = _VIEWS.get(self)
        if type(self) is not PlatformAttestationView or self._verification_token is not _TOKEN or state is None: _fail("ATTESTATION_VERIFIED_INVALID")
        _activation_first(state.inputs, state.minted_now)
        _same_evidence(state.evidence)
        _same_public(self, state.public)
        try: fields, raw = _verify(*state.inputs, state.minted_now)
        except Exception as error: raise AttestationFailure("ATTESTATION_VERIFIED_INVALID") from error
        try: parsed = loads_composite_canonical(self._canonical_source_bytes)
        except Exception as error: raise AttestationFailure("ATTESTATION_VERIFIED_INVALID") from error
        if canonical_composite_bytes(parsed) != self._canonical_source_bytes or _fingerprint(_fields(self), self._canonical_source_bytes) != state.fingerprint or _fingerprint(fields, raw) != state.fingerprint: _fail("ATTESTATION_VERIFIED_INVALID")
    def require_dependencies(self, mapping: VerifiedMappingPolicy, adjunct_trust: VerifiedAdjunctTrustRegistry, activation: ActivationView, declaration: VerifiedDeclaration, report: VerifiedReport, now_epoch_seconds: int) -> None:
        self.require_verified(now_epoch_seconds)
        state = _VIEWS.get(self)
        if type(mapping) is not VerifiedMappingPolicy or type(adjunct_trust) is not VerifiedAdjunctTrustRegistry or type(activation) is not ActivationView or type(declaration) is not VerifiedDeclaration or type(report) is not VerifiedReport or state is None or any(current is not expected for current, expected in zip((mapping, adjunct_trust, activation, declaration, report), state.inputs[2:7])): _fail("ATTESTATION_DEPENDENCY_INVALID")

@dataclass(frozen=True)
class _EvidenceState:
    bundle: AttestationEvidenceBundle; sequences: tuple[object, object, object, object]
    pairs: tuple[tuple[object, VerifiedEnvelope, VerifiedEnvelope], ...]
    members: tuple[tuple[VerifiedEnvelope, ...], tuple[VerifiedEnvelope, ...], tuple[VerifiedEnvelope, ...]]
@dataclass(frozen=True)
class _State: inputs: tuple[object, ...]; minted_now: int; fingerprint: str; evidence: _EvidenceState; public: _PublicState
@dataclass(frozen=True)
class _PublicState:
    issuer: PrincipalBinding; host: HostIdentity; host_identity: PrincipalBinding; executed: tuple[object, ...]; controls: tuple[object, ...]; closures: tuple[ArtifactClosure, ...]
    host_rows: tuple[tuple[object, ...], tuple[object, ...]]; closure_parts: tuple[tuple[object, object, object, object], ...]; profiles: tuple[ProfileRow, ...]
    closure_rows: tuple[ArtifactClosure, ...]; profile_parts: tuple[tuple[object, object, object], ...]; profile_rows: tuple[ProfileRow, ...]
    digests: tuple[str, ...]; identities: tuple[PrincipalBinding, ...]; identity_rows: tuple[PrincipalBinding, ...]
_VIEWS: weakref.WeakKeyDictionary[PlatformAttestationView, _State] = weakref.WeakKeyDictionary()
def _evidence_state(bundle: AttestationEvidenceBundle) -> _EvidenceState:
    if type(bundle) is not AttestationEvidenceBundle: _fail("ATTESTATION_VERIFIED_INVALID")
    sequences = (bundle.classifier_pairs, bundle.host_records, bundle.profile_records, bundle.canary_records)
    if any(type(value) not in (tuple, list) for value in sequences): _fail("ATTESTATION_VERIFIED_INVALID")
    pairs = []
    for pair in sequences[0]:
        if type(pair) is not tuple or len(pair) != 2 or any(type(item) is not VerifiedEnvelope for item in pair): _fail("ATTESTATION_VERIFIED_INVALID")
        pairs.append((pair, pair[0], pair[1]))
    members = tuple(tuple(value) for value in sequences[1:])
    if any(any(type(item) is not VerifiedEnvelope for item in value) for value in members): _fail("ATTESTATION_VERIFIED_INVALID")
    return _EvidenceState(bundle, sequences, tuple(pairs), members)
def _same_evidence(state: _EvidenceState) -> None:
    bundle, sequences = state.bundle, state.sequences
    if type(bundle) is not AttestationEvidenceBundle or any(current is not expected for current, expected in zip((bundle.classifier_pairs, bundle.host_records, bundle.profile_records, bundle.canary_records), sequences)): _fail("ATTESTATION_VERIFIED_INVALID")
    if len(sequences[0]) != len(state.pairs) or any(pair is not prior or type(pair) is not tuple or len(pair) != 2 or pair[0] is not first or pair[1] is not second for pair, (prior, first, second) in zip(sequences[0], state.pairs)): _fail("ATTESTATION_VERIFIED_INVALID")
    if any(len(current) != len(prior) or any(item is not expected for item, expected in zip(current, prior)) for current, prior in zip(sequences[1:], state.members)): _fail("ATTESTATION_VERIFIED_INVALID")
def _activation_first(inputs: tuple[object, ...], now: object) -> None:
    if type(now) is not int or isinstance(now, bool): _fail("ATTESTATION_VERIFIED_INVALID")
    _, _, mapping, registry, activation, *_ = inputs
    try: ActivationView.require_dependencies(activation, mapping, registry, now)
    except Exception as error: raise AttestationFailure("ATTESTATION_VERIFIED_INVALID") from error
def _public_state(view: PlatformAttestationView) -> _PublicState:
    host, closures, profiles, digests, identities = view.host, view.closures, view.profile_rows, view.evidence_envelope_sha256s, view.evidence_identities
    if type(host) is not HostIdentity or type(view.attestation_issuer_identity) is not PrincipalBinding or type(host.host_attestor_identity) is not PrincipalBinding or any(type(value) is not tuple for value in (host.executed_artifacts, host.control_results, closures, profiles, digests, identities)) or any(type(value) is not ArtifactClosure for value in closures) or any(type(value) is not ProfileRow for value in profiles) or any(type(value) is not PrincipalBinding for value in identities): _fail("ATTESTATION_VERIFIED_INVALID")
    return _PublicState(view.attestation_issuer_identity, host, host.host_attestor_identity, host.executed_artifacts, host.control_results, closures, (tuple(host.executed_artifacts), tuple(host.control_results)), tuple((row.classifier_identities, row.classifier_implementation_sha256s, row.classifier_dependency_set_sha256s, row.classifier_run_ids) for row in closures), profiles, tuple(closures), tuple((row.artifact_slot_ids, row.rc0_gate_evidence_sha256s, row.evidence_identity) for row in profiles), tuple(profiles), digests, identities, tuple(identities))
def _same_public(view: PlatformAttestationView, state: _PublicState) -> None:
    if view.attestation_issuer_identity is not state.issuer or view.host is not state.host or view.host.host_attestor_identity is not state.host_identity or view.host.executed_artifacts is not state.executed or view.host.control_results is not state.controls or view.closures is not state.closures or view.profile_rows is not state.profiles or view.evidence_envelope_sha256s is not state.digests or view.evidence_identities is not state.identities: _fail("ATTESTATION_VERIFIED_INVALID")
    rows = (tuple(view.host.executed_artifacts), tuple(view.host.control_results))
    if any(len(current) != len(expected) or any(item is not prior for item, prior in zip(current, expected)) for current, expected in zip(rows, state.host_rows)) or any(item is not expected for item, expected in zip(view.closures, state.closure_rows)) or any(item is not expected for item, expected in zip(view.profile_rows, state.profile_rows)) or any(item is not expected for item, expected in zip(view.evidence_identities, state.identity_rows)) or len(view.closures) != len(state.closure_parts) or len(view.profile_rows) != len(state.profile_parts) or any(any(current is not expected for current, expected in zip((row.classifier_identities, row.classifier_implementation_sha256s, row.classifier_dependency_set_sha256s, row.classifier_run_ids), parts)) for row, parts in zip(view.closures, state.closure_parts)) or any(any(current is not expected for current, expected in zip((row.artifact_slot_ids, row.rc0_gate_evidence_sha256s, row.evidence_identity), parts)) for row, parts in zip(view.profile_rows, state.profile_parts)): _fail("ATTESTATION_VERIFIED_INVALID")
def _fields(view: PlatformAttestationView) -> tuple[object, ...]: return tuple(getattr(view, key) for key in view.__dataclass_fields__ if key not in {"_canonical_source_bytes", "_verification_token"})
def _value(value: object) -> object:
    if value is None or type(value) in {str, bool}: return value
    if type(value) is int: return value
    if type(value) is bytes: return _sha(value)
    if type(value) is tuple: return [_value(item) for item in value]
    if type(value) is PrincipalBinding:
        parts = (value.role_id, value.subject_id, value.controlling_account_id, value.delegated_session_id, value.lane_id)
        if any(type(item) is not str for item in parts): _fail("ATTESTATION_VERIFIED_INVALID")
        return list(parts)
    kinds = (HostIdentity, ArtifactClosure, ProfileRow, HostControlResult)
    if type(value) in kinds:
        return {name: _value(getattr(value, name)) for name in value.__dataclass_fields__}
    from scripts.rc0_policy.platform_attestation_evidence import ExecutedArtifact
    if type(value) is ExecutedArtifact: return {name: _value(getattr(value, name)) for name in value.__dataclass_fields__}
    _fail("ATTESTATION_VERIFIED_INVALID")
def _projection(fields: tuple[object, ...]) -> list[object]:
    if type(fields) is not tuple or len(fields) != 15: _fail("ATTESTATION_VERIFIED_INVALID")
    return [_value(item) for item in fields]
def _fingerprint(fields: tuple[object, ...], raw: bytes) -> str: return _sha(canonical_bytes({"view": _projection(fields), "source": _sha(raw)}))
def _verified(value: object, kind: type[object], now: int, code: str) -> None:
    if type(value) is not kind: _fail(code)
    try: kind.require_verified(value, now)
    except Exception as error: raise AttestationFailure(code) from error
def _microseconds(value: object) -> int:
    if type(value) is not str: raise ValueError("timestamp")
    return timestamp_epoch_seconds(value) * 1_000_000 + (int(value[20:26]) if len(value) == 27 else 0)
def _outer(value: object, registry: VerifiedAdjunctTrustRegistry, now: int) -> tuple[dict[str, object], PrincipalBinding]:
    if type(value) is not VerifiedEnvelope: _fail("ATTESTATION_ENVELOPE_INVALID")
    try:
        require_fixture_verified(value); payload = loads_canonical(value.payload_canonical_bytes); raw = (ROOT / "docs/schemas/rc0-platform-scope-attestation-v1.schema.json").read_bytes()
        if _sha(raw) != dict(registry.adjunct_schema_digests).get(ATTESTATION): _fail("REGISTRY_SCHEMA_MISMATCH")
        AdjunctSchemaStore({ATTESTATION: raw}).validate(ATTESTATION, value.payload_schema_sha256, payload)
    except AttestationFailure: raise
    except Exception as error: raise AttestationFailure("ATTESTATION_ENVELOPE_INVALID") from error
    identity = principal(value); expected = dict(registry.role_principal_constraints).get("qualification_aggregator")
    fields = (value.payload_schema_id, value.payload_schema_sha256, value.payload_sha256, value.issued_at, value.not_before, value.expires_at)
    try: observed, issued, deadline, expires = (_microseconds(item) for item in (payload.get("observed_at"), value.issued_at, payload.get("freshness_deadline"), value.expires_at))
    except Exception as error: raise AttestationFailure("ATTESTATION_FRESHNESS_MISMATCH") from error
    if not observed <= issued <= now * 1_000_000 <= deadline <= expires: _fail("ATTESTATION_FRESHNESS_MISMATCH")
    if any(type(item) is not str for item in fields) or type(value.not_before_epoch_seconds) is not int or type(value.issued_at_epoch_seconds) is not int or type(value.expires_at_epoch_seconds) is not int or not value.not_before_epoch_seconds <= value.issued_at_epoch_seconds <= now <= value.expires_at_epoch_seconds or value.payload_schema_id != ATTESTATION or value.payload_sha256 != _sha(value.payload_canonical_bytes) or canonical_bytes(payload) != value.payload_canonical_bytes or type(expected) is not PrincipalBinding or tuple(identity.__dict__.values()) != tuple(expected.__dict__.values()): _fail("ATTESTATION_ROLE_MISMATCH")
    return payload, identity
def _binding(payload: dict[str, object], mapping: VerifiedMappingPolicy, activation: ActivationView, declaration: VerifiedDeclaration, report: VerifiedReport) -> AttestationGateBinding:
    common = payload.get("common_binding_group")
    required = (("repository_id", "gocode"), ("mapping_policy_envelope_sha256", mapping.envelope_sha256), ("adjunct_trust_registry_envelope_sha256", mapping.adjunct_trust_registry_envelope_sha256), ("adjunct_trust_registry_payload_sha256", mapping.adjunct_trust_registry_payload_sha256), ("rc0_qualification_policy_digest", mapping.rc0_qualification_policy_digest), ("active_activation_snapshot_envelope_sha256", activation.snapshot_envelope_sha256))
    if type(common) is not dict or common != report_common_binding_group(report) or any(payload.get(key) != wanted for key, wanted in required) or payload.get("common_binding_group_payload_sha256") != _sha(canonical_bytes(common)) or payload["common_binding_group_payload_sha256"] != declaration.common_binding_group_payload_sha256 or payload["common_binding_group_payload_sha256"] != report.common_binding_group_payload_sha256 or payload["rc0_qualification_policy_digest"] != declaration.rc0_qualification_policy_digest: _fail("ATTESTATION_LINEAGE_MISMATCH")
    row = next((item for item in mapping.platform_scopes if item.platform_scope_id == payload.get("platform_scope_id")), None)
    if row is None or payload.get("qualification_class") != row.qualification_class: _fail("ATTESTATION_SCOPE_MISMATCH")
    return AttestationGateBinding("gocode", mapping.envelope_sha256, activation.snapshot_envelope_sha256, payload["common_binding_group_payload_sha256"], row.platform_scope_id)
def _declared(payload: dict[str, object], bundle: AttestationEvidenceBundle) -> dict[str, tuple[VerifiedEnvelope, ...]]:
    actual, wanted = dict(groups(bundle)), dict(digests(bundle))
    for name, values in wanted.items():
        if type(payload.get(name)) is not list or tuple(payload[name]) != values or len(set(values)) != len(values): _fail("ATTESTATION_EVIDENCE_SET_MISMATCH")
    return actual
def _fresh(records: list[tuple[dict[str, object], PrincipalBinding, VerifiedEnvelope]], now: int) -> tuple[PrincipalBinding, ...]:
    identities = []
    for payload, identity, envelope in records:
        try: observed, issued, deadline, expires = (_microseconds(value) for value in (payload.get("observed_at"), envelope.issued_at, payload.get("freshness_deadline"), envelope.expires_at))
        except Exception as error: raise AttestationFailure("EVIDENCE_FRESHNESS_MISMATCH") from error
        if not observed <= issued <= now * 1_000_000 <= deadline <= expires: _fail("EVIDENCE_FRESHNESS_MISMATCH")
        identities.append(identity)
    result = tuple(sorted(set(identities), key=lambda item: canonical_bytes([item.role_id, item.subject_id, item.controlling_account_id, item.delegated_session_id, item.lane_id])))
    if not result: _fail("EVIDENCE_IDENTITY_MISMATCH")
    return result
def _source(attestation: VerifiedEnvelope, bundle: AttestationEvidenceBundle, mapping: VerifiedMappingPolicy, registry: VerifiedAdjunctTrustRegistry, activation: ActivationView, declaration: VerifiedDeclaration, report: VerifiedReport) -> bytes:
    configured = sorted([[name, [[schema, dict(registry.adjunct_schema_digests)[schema]]]] for name, schema in CATEGORIES])
    value = {"attestation_envelope": loads_canonical(attestation.envelope_canonical_bytes), "evidence_envelopes": sorted([[name, [loads_canonical(raw) for raw in values]] for name, values in source(bundle)]), "mapping_source": loads_canonical(mapping._canonical_source_bytes), "registry_envelope": loads_canonical(registry.envelope_canonical_bytes), "activation_canonical_source": loads_canonical(activation._canonical_source_bytes), "declaration_envelope": loads_canonical(declaration._canonical_declaration_envelope_bytes), "report_envelope": loads_canonical(report._canonical_report_envelope_bytes), "configured_bundle_category_pair_digests": configured}
    return canonical_composite_bytes(value)
def _verify(attestation: object, bundle: object, mapping: object, registry: object, activation: object, declaration: object, report: object, now: int) -> tuple[tuple[object, ...], bytes]:
    if type(now) is not int or isinstance(now, bool): _fail("ATTESTATION_INPUT_INVALID")
    if type(activation) is not ActivationView or type(mapping) is not VerifiedMappingPolicy or type(registry) is not VerifiedAdjunctTrustRegistry: _fail("ACTIVATION_VERIFIED_INVALID")
    try: ActivationView.require_dependencies(activation, mapping, registry, now)
    except Exception as error: raise AttestationFailure("ACTIVATION_VERIFIED_INVALID") from error
    if activation.state != "active" or type(activation.runner_consumer_identity) is not PrincipalBinding or type(activation.downstream_consumer_identity) is not PrincipalBinding: _fail("ACTIVATION_CONSUMER_MISMATCH")
    if type(bundle) is not AttestationEvidenceBundle: _fail("ATTESTATION_INPUT_INVALID")
    _verified(mapping, VerifiedMappingPolicy, now, "MAPPING_VERIFIED_INVALID"); _verified(registry, VerifiedAdjunctTrustRegistry, now, "REGISTRY_VERIFIED_INVALID")
    if type(declaration) is not VerifiedDeclaration or type(report) is not VerifiedReport: _fail("DECLARATION_VERIFIED_INVALID")
    try: VerifiedDeclaration.require_dependencies(declaration, mapping, report, now); VerifiedReport.require_dependencies(report, mapping, now)
    except Exception as error: raise AttestationFailure("DECLARATION_VERIFIED_INVALID") from error
    if declaration.report is not report or mapping.adjunct_trust is not registry or activation.mapping_policy_envelope_sha256 != mapping.envelope_sha256: _fail("ATTESTATION_DEPENDENCY_MISMATCH")
    payload, issuer = _outer(attestation, registry, now)
    if payload.get("producing_lane_id") != attestation.issuer_lane_id: _fail("ATTESTATION_LINEAGE_MISMATCH")
    binding, by_name = _binding(payload, mapping, activation, declaration, report), _declared(payload, bundle); records = []
    for name, schema in CATEGORIES:
        for item in by_name[name]:
            parsed, identity = evidence_record(item, registry, schema); records.append((parsed, identity, item))
    for parsed, _, _ in records:
        if any(parsed.get(key) != payload.get(key) for key in ("repository_id", "mapping_policy_envelope_sha256", "adjunct_trust_registry_envelope_sha256", "adjunct_trust_registry_payload_sha256", "rc0_qualification_policy_digest", "active_activation_snapshot_envelope_sha256", "common_binding_group_payload_sha256", "platform_scope_id")) or canonical_bytes(parsed.get("common_binding_group")) != canonical_bytes(payload.get("common_binding_group")): _fail("EVIDENCE_LINEAGE_MISMATCH")
    identities = _fresh(records, now); hosts = by_name["host_evidence_records"]
    expected_profiles = tuple(row for row in mapping.profile_states if row.platform_scope_id == binding.platform_scope_id)
    expected_slots = tuple(row for row in mapping.artifact_slots if row.platform_scope_id == binding.platform_scope_id)
    expected_canaries = tuple(row for row in expected_profiles if row.state == "external_canary_only")
    if len(hosts) != 1 or len(bundle.classifier_pairs) != len(expected_slots) or len(by_name["profile_evidence_records"]) != len(expected_profiles) - len(expected_canaries) or len(by_name["canary_evidence_records"]) != len(expected_canaries): _fail("ATTESTATION_EVIDENCE_SET_MISMATCH")
    wanted_profiles = {row.profile_id: row.state == "external_canary_only" for row in expected_profiles}
    actual_profiles = []
    for is_canary, name, schema in ((False, "profile_evidence_records", CATEGORIES[2][1]), (True, "canary_evidence_records", CATEGORIES[3][1])):
        actual_profiles.extend((item.get("profile_id"), is_canary) for item, _ in (evidence_record(record, registry, schema) for record in by_name[name]))
    if len(actual_profiles) != len(wanted_profiles) or dict(actual_profiles) != wanted_profiles: _fail("ATTESTATION_EVIDENCE_SET_MISMATCH")
    pair_slots = []
    for first, second in bundle.classifier_pairs:
        first_payload, _ = evidence_record(first, registry, CATEGORIES[0][1]); second_payload, _ = evidence_record(second, registry, CATEGORIES[0][1])
        if first.issuer_role != "artifact_classifier_a" or second.issuer_role != "artifact_classifier_b" or first_payload.get("artifact_slot_id") != second_payload.get("artifact_slot_id") or first_payload.get("platform_scope_id") != binding.platform_scope_id: _fail("CLASSIFIER_PAIR_MISMATCH")
        pair_slots.append(first_payload["artifact_slot_id"])
    if tuple(sorted(pair_slots)) != tuple(sorted(row.artifact_slot_id for row in expected_slots)): _fail("ARTIFACT_CLOSURE_SET_MISMATCH")
    host_payload, host_identity = evidence_record(hosts[0], registry, CATEGORIES[1][1]); controls = verify_host_policy(host_payload, mapping, binding.platform_scope_id, binding); host_view = host(host_payload, host_identity, controls)
    profile_rows = verify_profile_rows(profiles(by_name["profile_evidence_records"], registry, CATEGORIES[2][1]), profiles(by_name["canary_evidence_records"], registry, CATEGORIES[3][1]), mapping, report, binding.platform_scope_id)
    if (binding.platform_scope_id.startswith("macos")) != (len(by_name["canary_evidence_records"]) == 1): _fail("CANARY_EVIDENCE_SET_MISMATCH")
    closures = []
    for first, second in bundle.classifier_pairs:
        first_payload, _ = evidence_record(first, registry, CATEGORIES[0][1]); evidence_record(second, registry, CATEGORIES[0][1])
        if first.issuer_role != "artifact_classifier_a" or second.issuer_role != "artifact_classifier_b" or first_payload.get("platform_scope_id") != binding.platform_scope_id: _fail("CLASSIFIER_PAIR_MISMATCH")
        try: closure = verify_artifact_closure(first, second, hosts[0])
        except ArtifactClosureFailure as error: raise AttestationFailure(error.code) from error
        manifest = first_payload.get("artifact_manifest_payload")
        verify_shape_results(manifest.get("shape_results") if type(manifest) is dict else None, closure.artifact_slot_id, binding, mapping); closures.append(closure)
    closures = tuple(sorted(closures, key=lambda item: item.artifact_slot_id)); expected = tuple(sorted(item.artifact_slot_id for item in expected_slots))
    if tuple(item.artifact_slot_id for item in closures) != expected: _fail("ARTIFACT_CLOSURE_SET_MISMATCH")
    scope = next(item for item in mapping.platform_scopes if item.platform_scope_id == binding.platform_scope_id); raw = _source(attestation, bundle, mapping, registry, activation, declaration, report)
    return (attestation.envelope_sha256, "gocode", issuer, mapping.envelope_sha256, mapping.rc0_qualification_policy_digest, activation.snapshot_envelope_sha256, binding.common_binding_group_payload_sha256, binding.platform_scope_id, scope.qualification_class, scope.support_disposition, host_view, closures, profile_rows, tuple(sorted(value for _, rows in digests(bundle) for value in rows)), identities), raw
def verify_platform_attestation(attestation: VerifiedEnvelope, evidence: AttestationEvidenceBundle, mapping: VerifiedMappingPolicy, adjunct_trust: VerifiedAdjunctTrustRegistry, activation: ActivationView, declaration: VerifiedDeclaration, report: VerifiedReport, now_epoch_seconds: int) -> PlatformAttestationView:
    fields, raw = _verify(attestation, evidence, mapping, adjunct_trust, activation, declaration, report, now_epoch_seconds); names = tuple(key for key in PlatformAttestationView.__dataclass_fields__ if key not in {"_canonical_source_bytes", "_verification_token"}); view = PlatformAttestationView(_TOKEN, **dict(zip(names, fields)), _canonical_source_bytes=raw); _VIEWS[view] = _State((attestation, evidence, mapping, adjunct_trust, activation, declaration, report), now_epoch_seconds, _fingerprint(fields, raw), _evidence_state(evidence), _public_state(view)); view.require_verified(now_epoch_seconds); return view
