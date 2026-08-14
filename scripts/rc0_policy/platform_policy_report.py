"""Opaque fixture-only verification-report and declaration joins."""

from __future__ import annotations

import hashlib
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from scripts.rc0_policy.bindings import validate_report_against_policy as base_validate
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import (
    AdjunctSchemaStore, EnvelopeResolver, PrincipalBinding, VerifiedEnvelope, require_fixture_verified,
    timestamp_epoch_seconds,
)
from scripts.rc0_policy.platform_policy_errors import PolicyFailure
from scripts.rc0_policy.platform_policy_mapping import Rc0TrustPolicyView, VerifiedMappingPolicy
from scripts.rc0_policy.rules import BINDING_FIELDS
from scripts.rc0_policy.schemas import SCHEMA_FILES, validate_schema


ROOT = Path(__file__).resolve().parents[2]
_TOKEN = object()
@dataclass(frozen=True)
class _IssuedState:
    fingerprint: str; mapping: VerifiedMappingPolicy; report: weakref.ReferenceType[VerifiedReport] | None
_ISSUED: weakref.WeakKeyDictionary[object, _IssuedState] = weakref.WeakKeyDictionary()
_REPORT_SCHEMA = "gocode.rc0.schema.verification-report/3"
_DECLARATION_SCHEMA = "gocode.rc0.qualified-declaration/1"
_ADJUNCT_SCHEMA_FILES = {_DECLARATION_SCHEMA: "rc0-qualified-declaration-v1.schema.json"}


def _sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()
def _fail(code: str) -> None: raise PolicyFailure(code)
def _principal(e: VerifiedEnvelope) -> PrincipalBinding: return PrincipalBinding(e.issuer_role, e.issuer_subject_id, e.issuer_controlling_account_id, e.issuer_delegated_session_id, e.issuer_lane_id)
def _role(mapping: VerifiedMappingPolicy, role: str) -> PrincipalBinding:
    value = dict(mapping.adjunct_trust.role_principal_constraints).get(role)
    if value is None: _fail("REGISTRY_ROLE_MISMATCH")
    return value
def _payload(e: VerifiedEnvelope) -> dict[str, object]:
    try: require_fixture_verified(e); value = loads_canonical(e.payload_canonical_bytes)
    except Exception as error: raise PolicyFailure("FIXTURE_ENVELOPE_INVALID") from error
    if type(value) is not dict: _fail("PAYLOAD_INVALID")
    return value
def _window(raw: bytes, now: int, code: str) -> dict[str, object]:
    try:
        outer = loads_canonical(raw)
        if type(now) is not int or isinstance(now, bool) or type(outer) is not dict or canonical_bytes(outer) != raw:
            _fail(code)
        issued, not_before, expires = (timestamp_epoch_seconds(outer[name]) for name in ("issued_at", "not_before", "expires_at"))
        if not not_before <= issued <= now <= expires: _fail(code)
        payload = outer.get("payload")
        if type(payload) is not dict or _sha(canonical_bytes(payload)) != outer.get("payload_sha256"): _fail(code)
        return outer
    except PolicyFailure: raise
    except Exception as error: raise PolicyFailure(code) from error
def _fingerprint(source: bytes, nested: object | None = None) -> str:
    return _sha(source + (b"" if nested is None else b"\0" + str(id(nested)).encode() + b"\0" + nested.envelope_sha256.encode()))
def _remember(view: object, source: bytes, mapping: VerifiedMappingPolicy, nested: object | None = None) -> None:
    _ISSUED[view] = _IssuedState(_fingerprint(source, nested), mapping, None if nested is None else weakref.ref(nested))
def _issued(view: object, source: bytes, nested: object | None = None) -> _IssuedState:
    value = _ISSUED.get(view)
    if value is None or value.fingerprint != _fingerprint(source, nested) or (nested is not None and value.report is not None and value.report() is not nested): _fail("REPORT_VERIFIED_INVALID")
    return value
def _mapping(state: _IssuedState, now: int, code: str) -> VerifiedMappingPolicy:
    mapping = state.mapping
    if type(mapping) is not VerifiedMappingPolicy: _fail(code)
    try: VerifiedMappingPolicy.require_verified(mapping, now)
    except Exception as error: raise PolicyFailure(code) from error
    return mapping
def _same_principal(actual: object, expected: PrincipalBinding) -> bool:
    return type(actual) is PrincipalBinding and type(actual.role_id) is str and type(actual.subject_id) is str and type(actual.controlling_account_id) is str and type(actual.delegated_session_id) is str and type(actual.lane_id) is str and (actual.role_id, actual.subject_id, actual.controlling_account_id, actual.delegated_session_id, actual.lane_id) == (expected.role_id, expected.subject_id, expected.controlling_account_id, expected.delegated_session_id, expected.lane_id)
def _same_gate(actual: object, expected: RequiredGateResultRow) -> bool:
    return type(actual) is RequiredGateResultRow and type(actual.gate_id) is str and type(actual.stage) is str and type(actual.execution_outcome) is str and type(actual.gate_result) is str and type(actual.blocked_reason) is type(expected.blocked_reason) and type(actual.canonical_row_bytes) is bytes and (actual.gate_id, actual.stage, actual.execution_outcome, actual.gate_result, actual.blocked_reason, actual.canonical_row_bytes) == (expected.gate_id, expected.stage, expected.execution_outcome, expected.gate_result, expected.blocked_reason, expected.canonical_row_bytes)
def _same_artifact(actual: object, expected: ReportArtifactBinding) -> bool:
    return type(actual) is ReportArtifactBinding and type(actual.relative_path) is str and type(actual.sha256) is str and type(actual.size) is int and type(actual.locator) is str and (actual.relative_path, actual.sha256, actual.size, actual.locator) == (expected.relative_path, expected.sha256, expected.size, expected.locator)
def _same_rows(actual: object, expected: tuple[object, ...], row: Callable[[object, object], bool]) -> bool:
    return type(actual) is tuple and len(actual) == len(expected) and all(row(value, wanted) for value, wanted in zip(actual, expected))
def _same_report(view: VerifiedReport, expected: Mapping[str, object]) -> bool:
    return type(view.envelope_sha256) is str and type(view.repository_id) is str and _same_principal(view.reporter_identity, expected["reporter_identity"]) and type(view.common_binding_group_payload_sha256) is str and type(view.rc0_qualification_policy_digest) is str and type(view.required_gate_set_payload_sha256) is str and type(view.artifact_set_payload_sha256) is str and _same_rows(view.required_gate_results, expected["required_gate_results"], _same_gate) and _same_rows(view.artifact_bindings, expected["artifact_bindings"], _same_artifact) and type(view._canonical_report_envelope_bytes) is bytes and (view.envelope_sha256, view.repository_id, view.common_binding_group_payload_sha256, view.rc0_qualification_policy_digest, view.required_gate_set_payload_sha256, view.artifact_set_payload_sha256, view._canonical_report_envelope_bytes) == (expected["envelope_sha256"], expected["repository_id"], expected["common_binding_group_payload_sha256"], expected["rc0_qualification_policy_digest"], expected["required_gate_set_payload_sha256"], expected["artifact_set_payload_sha256"], expected["_canonical_report_envelope_bytes"])
def _same_declaration(view: VerifiedDeclaration, expected: Mapping[str, object]) -> bool:
    return type(view.envelope_sha256) is str and type(view.repository_id) is str and _same_principal(view.declarer_identity, expected["declarer_identity"]) and type(view.common_binding_group_payload_sha256) is str and type(view.rc0_qualification_policy_digest) is str and type(view.verification_report_envelope_sha256) is str and type(view.required_gate_set_payload_sha256) is str and type(view.artifact_set_payload_sha256) is str and view.report is expected["report"] and type(view._canonical_declaration_envelope_bytes) is bytes and (view.envelope_sha256, view.repository_id, view.common_binding_group_payload_sha256, view.rc0_qualification_policy_digest, view.verification_report_envelope_sha256, view.required_gate_set_payload_sha256, view.artifact_set_payload_sha256, view._canonical_declaration_envelope_bytes) == (expected["envelope_sha256"], expected["repository_id"], expected["common_binding_group_payload_sha256"], expected["rc0_qualification_policy_digest"], expected["verification_report_envelope_sha256"], expected["required_gate_set_payload_sha256"], expected["artifact_set_payload_sha256"], expected["_canonical_declaration_envelope_bytes"])


@dataclass(frozen=True)
class RequiredGateResultRow:
    gate_id: str; stage: str; execution_outcome: str; gate_result: str; blocked_reason: str | None; canonical_row_bytes: bytes


@dataclass(frozen=True)
class ReportArtifactBinding:
    relative_path: str; sha256: str; size: int; locator: str


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class VerifiedReport:
    envelope_sha256: str; repository_id: str; reporter_identity: PrincipalBinding; common_binding_group_payload_sha256: str; rc0_qualification_policy_digest: str; required_gate_set_payload_sha256: str; artifact_set_payload_sha256: str; required_gate_results: tuple[RequiredGateResultRow, ...]; artifact_bindings: tuple[ReportArtifactBinding, ...]; _canonical_report_envelope_bytes: bytes; _verification_token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_verification_token"}: raise TypeError("VerifiedReport is verifier-owned")
        for key, value in fields.items(): object.__setattr__(self, key, value)
        object.__setattr__(self, "_verification_token", token)
    def require_verified(self, now_epoch_seconds: int) -> None:
        if type(self) is not VerifiedReport or self._verification_token is not _TOKEN or type(self._canonical_report_envelope_bytes) is not bytes: _fail("REPORT_VERIFIED_INVALID")
        _mapping(_issued(self, self._canonical_report_envelope_bytes), now_epoch_seconds, "REPORT_VERIFIED_INVALID")
        outer = _window(self._canonical_report_envelope_bytes, now_epoch_seconds, "REPORT_VERIFIED_INVALID")
        payload = outer["payload"]
        expected = _report_view_fields(outer, payload)
        if not _same_report(self, expected): _fail("REPORT_VERIFIED_INVALID")
    def require_dependencies(self, mapping: VerifiedMappingPolicy, now_epoch_seconds: int) -> None:
        try:
            if type(self) is not VerifiedReport or type(mapping) is not VerifiedMappingPolicy: _fail("REPORT_VERIFIED_INVALID")
            state = _issued(self, self._canonical_report_envelope_bytes)
            if state.mapping is not mapping: _fail("REPORT_VERIFIED_INVALID")
            VerifiedReport.require_verified(self, now_epoch_seconds)
        except PolicyFailure: raise
        except Exception as error: raise PolicyFailure("REPORT_VERIFIED_INVALID") from error


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class VerifiedDeclaration:
    envelope_sha256: str; repository_id: str; declarer_identity: PrincipalBinding; common_binding_group_payload_sha256: str; rc0_qualification_policy_digest: str; verification_report_envelope_sha256: str; required_gate_set_payload_sha256: str; artifact_set_payload_sha256: str; report: VerifiedReport; _canonical_declaration_envelope_bytes: bytes; _verification_token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_verification_token"}: raise TypeError("VerifiedDeclaration is verifier-owned")
        for key, value in fields.items(): object.__setattr__(self, key, value)
        object.__setattr__(self, "_verification_token", token)
    def require_verified(self, now_epoch_seconds: int) -> None:
        if type(self) is not VerifiedDeclaration or self._verification_token is not _TOKEN or type(self._canonical_declaration_envelope_bytes) is not bytes or type(self.report) is not VerifiedReport or type(self.report._canonical_report_envelope_bytes) is not bytes: _fail("DECLARATION_VERIFIED_INVALID")
        try: state = _issued(self, self._canonical_declaration_envelope_bytes, self.report)
        except PolicyFailure as error: raise PolicyFailure("DECLARATION_VERIFIED_INVALID") from error
        mapping = _mapping(state, now_epoch_seconds, "DECLARATION_VERIFIED_INVALID")
        try: report_state = _issued(self.report, self.report._canonical_report_envelope_bytes)
        except PolicyFailure as error: raise PolicyFailure("DECLARATION_VERIFIED_INVALID") from error
        if report_state.mapping is not mapping: _fail("DECLARATION_VERIFIED_INVALID")
        outer = _window(self._canonical_declaration_envelope_bytes, now_epoch_seconds, "DECLARATION_VERIFIED_INVALID")
        payload = outer["payload"]
        VerifiedReport.require_verified(self.report, now_epoch_seconds)
        if self.report.envelope_sha256 != payload.get("verification_report_envelope_sha256"): _fail("DECLARATION_VERIFIED_INVALID")
        expected = _declaration_view_fields(outer, payload, self.report)
        if not _same_declaration(self, expected): _fail("DECLARATION_VERIFIED_INVALID")
    def require_dependencies(self, mapping: VerifiedMappingPolicy, report: VerifiedReport, now_epoch_seconds: int) -> None:
        try:
            if type(self) is not VerifiedDeclaration or type(mapping) is not VerifiedMappingPolicy or type(report) is not VerifiedReport or self.report is not report: _fail("DECLARATION_VERIFIED_INVALID")
            state = _issued(self, self._canonical_declaration_envelope_bytes, self.report)
            report_state = _issued(report, report._canonical_report_envelope_bytes)
            if state.mapping is not mapping or report_state.mapping is not mapping: _fail("DECLARATION_VERIFIED_INVALID")
            VerifiedReport.require_dependencies(report, mapping, now_epoch_seconds)
            VerifiedDeclaration.require_verified(self, now_epoch_seconds)
        except PolicyFailure as error:
            if str(error) == "REPORT_VERIFIED_INVALID": raise PolicyFailure("DECLARATION_VERIFIED_INVALID") from error
            raise
        except Exception as error: raise PolicyFailure("DECLARATION_VERIFIED_INVALID") from error


def _projected_rows(report: Mapping[str, object], artifact: bool) -> list[dict[str, object]]:
    key = "exact_artifact_bindings" if artifact else "required_gate_results"; rows = report.get(key)
    fields = ("relative_path", "sha256", "size", "locator") if artifact else ("gate_id", "stage", "execution_outcome", "gate_result", "blocked_reason", "binding")
    if type(rows) is not list: _fail("REPORT_PROJECTION_MISMATCH")
    kept = [{name: row[name] for name in fields if name in row} for row in rows if type(row) is dict]
    if len(kept) != len(rows) or len({canonical_bytes(row) for row in kept}) != len(kept): _fail("REPORT_PROJECTION_MISMATCH")
    if artifact:
        kept.sort(key=lambda row: (row["relative_path"].encode(), row["sha256"].encode(), str(row["size"]).encode(), row["locator"].encode()))
    else:
        kept.sort(key=lambda row: (row["gate_id"].encode(), row["stage"].encode(), canonical_bytes(row)))
    return kept
def _projection(report: dict[str, object], artifact: bool) -> str:
    kept = _projected_rows(report, artifact)
    domain = b"gocode.rc0.exact-artifact-bindings-projection/1\0" if artifact else b"gocode.rc0.required-gate-results-projection/1\0"
    return _sha(domain + canonical_bytes(kept))
def _report_projections(report: Mapping[str, object]) -> tuple[tuple[RequiredGateResultRow, ...], tuple[ReportArtifactBinding, ...]]:
    gates = tuple(RequiredGateResultRow(row["gate_id"], row["stage"], row["execution_outcome"], row["gate_result"], row.get("blocked_reason"), canonical_bytes(row)) for row in _projected_rows(report, False))
    artifacts = tuple(ReportArtifactBinding(row["relative_path"], row["sha256"], row["size"], row["locator"]) for row in _projected_rows(report, True))
    return gates, artifacts
def _common(report: Mapping[str, object]) -> dict[str, object]:
    return {name: report[name] for name in BINDING_FIELDS}


def report_common_binding_group(report: VerifiedReport) -> dict[str, object]:
    if type(report) is not VerifiedReport or type(report._canonical_report_envelope_bytes) is not bytes:
        _fail("REPORT_VERIFIED_INVALID")
    try:
        outer = loads_canonical(report._canonical_report_envelope_bytes)
        payload = outer["payload"]
        if type(payload) is not dict:
            _fail("REPORT_VERIFIED_INVALID")
        return _common(payload)
    except PolicyFailure:
        raise
    except Exception as error:
        raise PolicyFailure("REPORT_VERIFIED_INVALID") from error
def _report_view_fields(outer: Mapping[str, object], report: Mapping[str, object]) -> dict[str, object]:
    gates, artifacts = _report_projections(report)
    return {"envelope_sha256": _sha(canonical_bytes(outer)), "repository_id": report["repository_id"], "reporter_identity": PrincipalBinding(outer["issuer_role"], outer["issuer_subject_id"], outer["issuer_controlling_account_id"], outer["issuer_delegated_session_id"], outer["issuer_lane_id"]), "common_binding_group_payload_sha256": _sha(canonical_bytes(_common(report))), "rc0_qualification_policy_digest": report["policy_digest"], "required_gate_set_payload_sha256": _projection(dict(report), False), "artifact_set_payload_sha256": _projection(dict(report), True), "required_gate_results": gates, "artifact_bindings": artifacts, "_canonical_report_envelope_bytes": canonical_bytes(outer)}
def _declaration_view_fields(outer: Mapping[str, object], payload: Mapping[str, object], report: VerifiedReport) -> dict[str, object]:
    return {"envelope_sha256": _sha(canonical_bytes(outer)), "repository_id": payload["repository_id"], "declarer_identity": PrincipalBinding(outer["issuer_role"], outer["issuer_subject_id"], outer["issuer_controlling_account_id"], outer["issuer_delegated_session_id"], outer["issuer_lane_id"]), "common_binding_group_payload_sha256": payload["common_binding_group_payload_sha256"], "rc0_qualification_policy_digest": payload["rc0_qualification_policy_digest"], "verification_report_envelope_sha256": payload["verification_report_envelope_sha256"], "required_gate_set_payload_sha256": payload["required_gate_set_payload_sha256"], "artifact_set_payload_sha256": payload["artifact_set_payload_sha256"], "report": report, "_canonical_declaration_envelope_bytes": canonical_bytes(outer)}
def _schema_digest(schema_id: str) -> str:
    try: return _sha(_schema_raw(schema_id))
    except Exception as error: raise PolicyFailure("SCHEMA_PIN_MISMATCH") from error
def _schema_raw(schema_id: str) -> bytes: return (ROOT / "docs/schemas" / (SCHEMA_FILES.get(schema_id) or _ADJUNCT_SCHEMA_FILES[schema_id])).read_bytes()
def _valid_schema(payload: dict[str, object], schema_id: str) -> bool:
    try:
        if schema_id in SCHEMA_FILES: return bool(validate_schema(payload, schema_id))
        AdjunctSchemaStore({schema_id: _schema_raw(schema_id)}).validate(schema_id, _schema_digest(schema_id), payload)
        return False
    except Exception: return True
def _trust_exact(value: Rc0TrustPolicyView, mapping: VerifiedMappingPolicy) -> None:
    retained = mapping.rc0_trust_policy
    if type(value) is not Rc0TrustPolicyView or value != retained or value.canonical_sha256 != _sha(value.canonical_bytes): _fail("RC0_MAPPING_SET_MISMATCH")
    try:
        if canonical_bytes(loads_canonical(value.canonical_bytes)) != value.canonical_bytes: _fail("RC0_MAPPING_SET_MISMATCH")
    except PolicyFailure: raise
    except Exception as error: raise PolicyFailure("RC0_MAPPING_SET_MISMATCH") from error
def _report_policy(report: Mapping[str, object], trust: Rc0TrustPolicyView, mapping: VerifiedMappingPolicy) -> None:
    policy = loads_canonical(trust.canonical_bytes)
    expected = {name: report[name] for name in BINDING_FIELDS}
    if report.get("policy_digest") != mapping.rc0_qualification_policy_digest or base_validate(report, policy, expected): _fail("REPORT_PROJECTION_MISMATCH")
    labels = ("source_candidate_gate", "production_qualification_gate", "evidence_seal_gate", "overall_candidate_gate")
    if any(report.get(name) != {"gate_result": "PASS"} for name in labels): _fail("REPORT_PROJECTION_MISMATCH")
    rows = report.get("required_gate_results")
    if type(rows) is not list or any(row.get("execution_outcome") != "PASS" or row.get("gate_result") != "PASS" or row.get("blocked_reason") is not None for row in rows if type(row) is dict): _fail("REPORT_PROJECTION_MISMATCH")


def validate_report_against_policy(report_envelope: VerifiedEnvelope, rc0_trust_policy: Rc0TrustPolicyView, mapping: VerifiedMappingPolicy, now_epoch_seconds: int) -> VerifiedReport:
    if type(mapping) is not VerifiedMappingPolicy: _fail("REPORT_PROJECTION_MISMATCH")
    VerifiedMappingPolicy.require_verified(mapping, now_epoch_seconds); _trust_exact(rc0_trust_policy, mapping); report = _payload(report_envelope)
    outer = _window(report_envelope.envelope_canonical_bytes, now_epoch_seconds, "REPORT_PROJECTION_MISMATCH")
    expected_schema = _schema_digest(_REPORT_SCHEMA)
    if report_envelope.payload_schema_id != _REPORT_SCHEMA or report_envelope.payload_schema_sha256 != expected_schema or dict(mapping.rc0_trust_policy.schema_id_hash_pairs).get(_REPORT_SCHEMA) != expected_schema or _principal(report_envelope) != _role(mapping, "rc0_qualification_reporter") or _valid_schema(report, _REPORT_SCHEMA): _fail("REPORT_PROJECTION_MISMATCH")
    _report_policy(report, rc0_trust_policy, mapping)
    view = VerifiedReport(_TOKEN, **_report_view_fields(outer, report)); _remember(view, view._canonical_report_envelope_bytes, mapping)
    VerifiedReport.require_verified(view, now_epoch_seconds)
    return view


def verify_qualified_declaration(declaration: VerifiedEnvelope, rc0_policy: Mapping[str, object], mapping: VerifiedMappingPolicy, resolve_envelope: EnvelopeResolver, verify_envelope: Callable[[bytes], VerifiedEnvelope], now_epoch_seconds: int) -> VerifiedDeclaration:
    if type(mapping) is not VerifiedMappingPolicy: _fail("DECLARATION_BINDING_MISMATCH")
    VerifiedMappingPolicy.require_verified(mapping, now_epoch_seconds)
    try: supplied = canonical_bytes(dict(rc0_policy))
    except Exception as error: raise PolicyFailure("RC0_MAPPING_SET_MISMATCH") from error
    if supplied != mapping.rc0_trust_policy.canonical_bytes: _fail("RC0_MAPPING_SET_MISMATCH")
    payload = _payload(declaration); outer = _window(declaration.envelope_canonical_bytes, now_epoch_seconds, "DECLARATION_BINDING_MISMATCH")
    expected_schema = dict(mapping.adjunct_schema_digests).get(_DECLARATION_SCHEMA)
    if expected_schema != _schema_digest(_DECLARATION_SCHEMA) or declaration.payload_schema_id != _DECLARATION_SCHEMA or declaration.payload_schema_sha256 != expected_schema or _principal(declaration) != _role(mapping, "rc0_qualification_declarer") or _valid_schema(payload, _DECLARATION_SCHEMA): _fail("DECLARATION_BINDING_MISMATCH")
    common, digest = payload.get("common_binding_group"), payload.get("verification_report_envelope_sha256")
    if type(common) is not dict or payload.get("common_binding_group_payload_sha256") != _sha(canonical_bytes(common)) or payload.get("runner_lane_id") != declaration.issuer_lane_id or type(digest) is not str or payload.get("rc0_qualification_policy_digest") != mapping.rc0_qualification_policy_digest: _fail("DECLARATION_BINDING_MISMATCH")
    try: raw = resolve_envelope(digest)
    except Exception: raw = None
    if type(raw) is not bytes or not raw or _sha(raw) != digest: _fail("REPORT_ENVELOPE_UNAVAILABLE")
    try: envelope = verify_envelope(raw)
    except Exception as error: raise PolicyFailure("REPORT_ENVELOPE_UNAVAILABLE") from error
    if type(envelope) is not VerifiedEnvelope or envelope.envelope_sha256 != digest or envelope.envelope_canonical_bytes != raw: _fail("REPORT_PROJECTION_MISMATCH")
    report = validate_report_against_policy(envelope, mapping.rc0_trust_policy, mapping, now_epoch_seconds)
    declarer = _principal(declaration)
    if common != _common(loads_canonical(report._canonical_report_envelope_bytes)["payload"]) or report.repository_id != payload["repository_id"] or report.reporter_identity == declarer or len({part for principal in (report.reporter_identity, declarer) for part in (principal.subject_id, principal.controlling_account_id, principal.delegated_session_id, principal.lane_id)}) != 8 or report.common_binding_group_payload_sha256 != payload["common_binding_group_payload_sha256"] or report.rc0_qualification_policy_digest != payload["rc0_qualification_policy_digest"] or report.required_gate_set_payload_sha256 != payload.get("required_gate_set_payload_sha256") or report.artifact_set_payload_sha256 != payload.get("artifact_set_payload_sha256"): _fail("REPORT_PROJECTION_MISMATCH")
    view = VerifiedDeclaration(_TOKEN, **_declaration_view_fields(outer, payload, report)); _remember(view, view._canonical_declaration_envelope_bytes, mapping, report)
    VerifiedDeclaration.require_verified(view, now_epoch_seconds)
    return view
