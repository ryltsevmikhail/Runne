"""One exact, inert three-platform graph for qualified-subject tests."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from scripts.rc0_policy.activation import fixture_verify_activation
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, VerifiedEnvelope, verify_signed_envelope
from scripts.rc0_policy.platform_attestation import verify_platform_attestation
from scripts.rc0_policy.platform_attestation_evidence import AttestationEvidenceBundle, digests
from scripts.rc0_policy.platform_matrix import normalized_platform_mapping_payload
from scripts.rc0_policy.platform_policy_report import _projection, verify_qualified_declaration
from scripts.rc0_policy.qualified_subject import _profile_digest, fixture_verify_qualified_subject
from scripts.tests.rc0_platform_attestation_trust_support import CONTROLS, common, digest, envelope, manifest
from scripts.tests.rc0_platform_activation_support import valid_active_fixture
from scripts.tests.rc0_platform_envelope_support import _NOW, _fixture_envelope, _fixture_schema_store, _sign, valid_fixture_envelope
from scripts.tests.rc0_platform_policy_support import _envelope, _principals, valid_declaration_fixture


@dataclass(frozen=True)
class SubjectFixture:
    subject: VerifiedEnvelope; declaration: object; report: object; mapping: object; activation: object; attestations: tuple[object, object, object]; now_epoch_seconds: int = _NOW
@dataclass(frozen=True)
class MatrixFixture:
    matrix: VerifiedEnvelope; subject: object; mapping: dict[str, object]; now_epoch_seconds: int; mutable_cell_fields: tuple[str, ...]


def _report(active: object, artifact_rows: list[dict[str, object]] | None = None) -> tuple[object, VerifiedEnvelope, object]:
    seed = valid_declaration_fixture(); mapping = active.mapping
    artifacts = artifact_rows or [{"relative_path": f"dist/{row.artifact_slot_id}", "sha256": hashlib.sha256(row.artifact_slot_id.encode()).hexdigest(), "size": index + 1, "locator": "cas:sha256:" + hashlib.sha256(row.artifact_slot_id.encode()).hexdigest()} for index, row in enumerate(mapping.artifact_slots)]
    binding = {"repository_id":"gocode","candidate_source_sha":"a" * 40,"evidence_attempt_id":"018f0000-0000-7000-8000-000000000000","observed_evidence_revision":"b" * 40,"evidence_bundle_digest":"d" * 64,"policy_revision":3,"policy_digest":mapping.rc0_qualification_policy_digest,"profile":"gocode.rc0.evidence-profile/3","exact_artifact_bindings":artifacts}
    gates = [{"gate_id": row[0], "stage": row[1], "execution_outcome":"PASS", "gate_result":"PASS", "binding":dict(binding)} for row in mapping.rc0_trust_policy.required_gate_projection]
    payload = {**binding,"schema_id":"gocode.rc0.schema.verification-report/3","required_gate_results":gates,"source_candidate_gate":{"gate_result":"PASS"},"production_qualification_gate":{"gate_result":"PASS"},"evidence_seal_gate":{"gate_result":"PASS"},"overall_candidate_gate":{"gate_result":"PASS"},"stage_dispositions":[{"stage":"RELEASE_APPROVAL","report_stage_disposition":"OUT_OF_SCOPE"},{"stage":"PUBLICATION_AUTHORIZATION","report_stage_disposition":"OUT_OF_SCOPE"}],"runner_identity":{"runner_class":"fixture","executable_digest":"e" * 64},"issued_at":"2026-08-09T00:00:00.000000Z"}
    schema_id = "gocode.rc0.schema.verification-report/3"; documents = dict(_fixture_schema_store()._schemas); root = __import__("pathlib").Path(__file__).resolve().parents[2]; documents[schema_id] = (root / "docs/schemas/rc0-verification-report-v3.schema.json").read_bytes(); store = AdjunctSchemaStore(documents)
    principals = _principals(); outer = _fixture_envelope(payload); outer.update(payload_schema_id=schema_id,payload_schema_sha256=hashlib.sha256(documents[schema_id]).hexdigest(),payload_sha256=digest(payload),issuer_role="rc0_qualification_reporter",issuer_subject_id=principals["rc0_qualification_reporter"]["subject_id"],issuer_controlling_account_id=principals["rc0_qualification_reporter"]["controlling_account_id"],issuer_delegated_session_id=principals["rc0_qualification_reporter"]["delegated_session_id"],issuer_lane_id=principals["rc0_qualification_reporter"]["lane_id"])
    _, verifier = valid_fixture_envelope(); report = verify_signed_envelope(_sign(outer), store, verifier, _NOW)
    declaration_payload = {"schema_version":"gocode.rc0.qualified-declaration/1","repository_id":"gocode","declaration_state":"RC0_QUALIFIED","common_binding_group":binding,"common_binding_group_payload_sha256":digest(binding),"rc0_qualification_policy_digest":mapping.rc0_qualification_policy_digest,"verification_report_envelope_sha256":report.envelope_sha256,"required_gate_set_payload_sha256":_projection({"required_gate_results":gates},False),"artifact_set_payload_sha256":_projection({"exact_artifact_bindings":artifacts},True),"runner_lane_id":principals["rc0_qualification_declarer"]["lane_id"]}
    declaration = _envelope(declaration_payload,"gocode.rc0.qualified-declaration/1","rc0_qualification_declarer",principals["rc0_qualification_declarer"])
    verify = lambda raw: verify_signed_envelope(raw, store, verifier, _NOW)
    return verify_qualified_declaration(declaration,seed.policy,mapping,lambda value: report.envelope_canonical_bytes if value == report.envelope_sha256 else b"",verify,_NOW), report, payload


def _attestation(active: object, declaration: object, report: object, scope_id: str, artifact_rows: dict[str, dict[str, object]] | None = None) -> object:
    mapping, registry = active.mapping, active.adjunct_trust; group = common(report); scope = next(row for row in mapping.platform_scopes if row.platform_scope_id == scope_id); slots = tuple(sorted((row for row in mapping.artifact_slots if row.platform_scope_id == scope_id), key=lambda row: row.artifact_slot_id))
    base = {"repository_id":"gocode","mapping_policy_envelope_sha256":mapping.envelope_sha256,"adjunct_trust_registry_envelope_sha256":registry.envelope_sha256,"adjunct_trust_registry_payload_sha256":registry.payload_sha256,"rc0_qualification_policy_digest":mapping.rc0_qualification_policy_digest,"active_activation_snapshot_envelope_sha256":active.snapshot.envelope_sha256,"common_binding_group":group,"common_binding_group_payload_sha256":digest(group),"platform_scope_id":scope_id}; pairs=[]; executed=[]
    for index,row in enumerate(slots):
        ordinal=next(index + 1 for index,item in enumerate(mapping.artifact_slots) if item.artifact_slot_id == row.artifact_slot_id); raw=dict(artifact_rows[row.artifact_slot_id]) if artifact_rows else {"relative_path":f"dist/{row.artifact_slot_id}","sha256":hashlib.sha256(row.artifact_slot_id.encode()).hexdigest(),"size":ordinal,"locator":"cas:sha256:" + hashlib.sha256(row.artifact_slot_id.encode()).hexdigest()}; item=manifest(row.artifact_slot_id,row.artifact_kind,raw); shared={**base,"schema_version":"gocode.rc0.artifact-measurement-record/1","artifact_slot_id":row.artifact_slot_id,"artifact_kind":row.artifact_kind,"relative_path":raw["relative_path"],"artifact_sha256":raw["sha256"],"size":raw["size"],"locator":raw["locator"],"artifact_manifest_payload":item,"artifact_manifest_payload_sha256":digest(item),"product_manifest_payload_sha256":"6" * 64,"observed_at":"2023-11-14T22:13:20Z","freshness_deadline":"2023-11-14T22:13:25Z"}; pairs.append((envelope({**shared,"classifier_implementation_sha256":"7" * 64,"classifier_dependency_set_sha256":"9" * 64,"classifier_lane_id":"artifact-a-lane","classifier_run_id":f"a-{index}"},"gocode.rc0.artifact-measurement-record/1","artifact_classifier_a"),envelope({**shared,"classifier_implementation_sha256":"8" * 64,"classifier_dependency_set_sha256":"a" * 64,"classifier_lane_id":"artifact-b-lane","classifier_run_id":f"b-{index}"},"gocode.rc0.artifact-measurement-record/1","artifact_classifier_b"))); executed.append({"artifact_slot_id":row.artifact_slot_id,"artifact_kind":row.artifact_kind,**raw,"artifact_manifest_payload_sha256":digest(item),"product_manifest_payload_sha256":"6" * 64})
    pin=next(row for row in mapping.host_identity_pins if row.platform_scope_id==scope_id); prefix={"Ubuntu":"linux","Windows":"windows","macOS":"macos"}[scope.os_family]; controls=[{"control_id":key,"result":"PASS" if key.startswith(prefix) else "NOT_APPLICABLE"} for key in sorted(CONTROLS)]; host=envelope({**base,"schema_version":"gocode.rc0.native-host-evidence-record/1","os_family":scope.os_family,"os_version":scope.os_version,"os_build":pin.os_build,"kernel_or_image_sha256":pin.kernel_or_image_sha256,"architecture":scope.architecture,"native_mode":"native","backend_id":pin.backend_id,"backend_version":pin.backend_version,"probe_set_payload_sha256":pin.probe_set_payload_sha256,"enforcement_descriptor_payload_sha256":pin.enforcement_descriptor_payload_sha256,"workflow_run_id":"host-run","executed_artifacts":executed,"control_results":controls,"observed_at":"2023-11-14T22:13:20Z","freshness_deadline":"2023-11-14T22:13:25Z"},"gocode.rc0.native-host-evidence-record/1","native_host_attestor")
    gates=sorted(hashlib.sha256(b"gocode.rc0.profile-gate-evidence-row/1\0" + row.canonical_row_bytes).hexdigest() for row in declaration.report.required_gate_results); profiles=[]; canaries=[]; outcomes={"required":"PASS","disabled_by_policy":"DISABLED_BY_POLICY","backend_unavailable":"BackendUnavailable","external_canary_only":"PASS"}
    for row in (row for row in mapping.profile_states if row.platform_scope_id==scope_id):
        item={**base,"profile_id":row.profile_id,"profile_revision":row.profile_revision,"profile_sha256":row.profile_sha256,"state":row.state,"artifact_slot_ids":[slot.artifact_slot_id for slot in slots],"rc0_gate_evidence_sha256s":gates,"canonical_result":outcomes[row.state],"observed_at":"2023-11-14T22:13:20Z","freshness_deadline":"2023-11-14T22:13:25Z"}; (canaries if row.state=="external_canary_only" else profiles).append(envelope({**item,**({"schema_version":"gocode.rc0.canary-evidence-record/1","operator_lane_id":"canary-lane"} if row.state=="external_canary_only" else {"schema_version":"gocode.rc0.profile-evidence-record/1"})},"gocode.rc0.canary-evidence-record/1" if row.state=="external_canary_only" else "gocode.rc0.profile-evidence-record/1","external_canary_operator" if row.state=="external_canary_only" else "native_host_attestor"))
    evidence=AttestationEvidenceBundle(tuple(pairs),(host,),tuple(profiles),tuple(canaries)); payload={**base,"schema_version":"gocode.rc0.platform-scope-attestation/1","qualification_class":scope.qualification_class,**{key:list(value) for key,value in digests(evidence)},"observed_at":"2023-11-14T22:13:19.999999Z","freshness_deadline":"2023-11-14T22:13:25.000000Z","producing_lane_id":"aggregate-lane"}; outer=envelope(payload,"gocode.rc0.platform-scope-attestation/1","qualification_aggregator")
    return verify_platform_attestation(outer,evidence,mapping,registry,active.activation,declaration,report,_NOW)


def valid_subject_fixture(artifact_rows: list[dict[str, object]] | None = None, subject_principal: dict[str, str] | None = None, match_artifacts: bool = False) -> SubjectFixture:
    raw=valid_active_fixture(); activation=fixture_verify_activation(raw.intent,(raw.runner_receipt,raw.downstream_receipt),raw.snapshot,raw.mapping,raw.adjunct_trust,raw.floor,raw.runner_subject_id,raw.downstream_subject_id,raw.expected_consumer_verifier_build_sha256s,_NOW); active=type("Active",(),{**raw.__dict__,"activation":activation})()
    declaration, _, _ = _report(active, artifact_rows); report=declaration.report; raw_rows=None if artifact_rows is None or not match_artifacts else dict(zip((row.artifact_slot_id for row in active.mapping.artifact_slots), artifact_rows)); attestations=tuple(_attestation(active,declaration,report,row.platform_scope_id,raw_rows) for row in active.mapping.platform_scopes); payload={"schema_version":"gocode.rc0.platform-qualified-subject/1","repository_id":"gocode","rc0_qualified_declaration_envelope_sha256":declaration.envelope_sha256,"rc0_verification_report_envelope_sha256":report.envelope_sha256,"common_binding_group_payload_sha256":declaration.common_binding_group_payload_sha256,"rc0_qualification_policy_digest":declaration.rc0_qualification_policy_digest,"mapping_policy_envelope_sha256":active.mapping.envelope_sha256,"active_activation_snapshot_envelope_sha256":activation.snapshot_envelope_sha256,"platform_attestation_envelope_sha256s":sorted(item.envelope_sha256 for item in attestations),"normalized_platform_mapping_payload_sha256":hashlib.sha256(normalized_platform_mapping_payload(attestations)).hexdigest(),"required_gate_set_payload_sha256":declaration.required_gate_set_payload_sha256,"profile_state_set_payload_sha256":_profile_digest(attestations),"artifact_set_payload_sha256":declaration.artifact_set_payload_sha256}
    return SubjectFixture(_envelope(payload,"gocode.rc0.platform-qualified-subject/1","qualification_aggregator",subject_principal or _principals()["qualification_aggregator"]),declaration,report,active.mapping,activation,attestations)


def replace_subject_field(value: VerifiedEnvelope, field: str, replacement: object) -> VerifiedEnvelope:
    payload=loads_canonical(value.payload_canonical_bytes); payload[field]=replacement; return envelope(payload,"gocode.rc0.platform-qualified-subject/1","qualification_aggregator")


def valid_matrix_fixture() -> MatrixFixture:
    fixture=valid_subject_fixture(); subject=fixture_verify_qualified_subject(fixture.subject,fixture.declaration,fixture.report,fixture.mapping,fixture.activation,fixture.attestations,fixture.now_epoch_seconds); mapping=loads_canonical(normalized_platform_mapping_payload(subject._attestations)); payload={"schema_version":"gocode.release.platform-qualification-matrix/2","repository_id":"gocode","platform_qualified_subject_envelope_sha256":subject.envelope_sha256,"normalized_platform_mapping":mapping,"normalized_platform_mapping_payload_sha256":hashlib.sha256(canonical_bytes(mapping)).hexdigest()}
    fields=("qualification_class","support_disposition","os_family","os_version","os_build","kernel_or_image_sha256","architecture","native_mode","profile_rows","artifact_rows","evidence_envelope_sha256s")
    return MatrixFixture(envelope(payload,"gocode.release.platform-qualification-matrix/2","qualification_aggregator"),subject,mapping,_NOW,fields)


def mutate_first_cell(value: dict[str, object], field: str) -> dict[str, object]:
    copy=loads_canonical(canonical_bytes(value)); cell=copy["cells"][0]
    if field == "profile_rows": cell[field][0]["profile_revision"] = "mutated"
    elif field == "artifact_rows": cell[field][0]["size"] += 1
    elif field == "evidence_envelope_sha256s": cell[field][0] = "f" * 64
    elif field in cell: cell[field] = ("changed" if isinstance(cell[field], str) else "changed")
    else: raise ValueError("unknown matrix field")
    return copy
