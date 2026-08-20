"""Fixture-only builders for post-RC0 platform policy verification tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, EnvelopeResolver, VerifiedEnvelope, verify_signed_envelope
from scripts.rc0_policy.adjunct_registry import verify_adjunct_trust_registry
from scripts.tests.rc0_platform_envelope_support import (
    _NOW, _fixture_envelope, _fixture_schema_store, _schema_digest, _sign, valid_fixture_envelope,
)


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "scripts/rc0_policy/fixtures/platform_scope/v1/valid/fixture-rc0-qualification-policy-v1.json"
RUNTIME_ADR = ROOT / "docs/adr/ADR-0027-v1-platform-scope.md"
DESKTOP_ADR = ROOT / "docs/desktop/adr/ADR-0015-v1-platform-scope.md"
DECISION = ROOT / "docs/decisions/v1-platform-scope-v1.json"
VALID = ROOT / "scripts/rc0_policy/fixtures/platform_scope/v1/valid"


@dataclass(frozen=True)
class MappingFixture:
    envelope: VerifiedEnvelope
    rc0_policy: Mapping[str, object]
    shared_decision_raw: bytes
    runtime_adr_raw: bytes
    desktop_adr_raw: bytes
    owner_acceptances: tuple[VerifiedEnvelope, ...]
    adjunct_trust: object
    claim_registry_raw: bytes
    base_document_universe_raw: bytes
    classified_delta_raw: bytes
    composed_document_universe_raw: bytes
    now_epoch_seconds: int = _NOW

    def arguments(self) -> dict[str, object]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class DeclarationFixture:
    declaration: VerifiedEnvelope
    policy: Mapping[str, object]
    mapping: object
    resolver: EnvelopeResolver
    verify_envelope: Callable[[bytes], VerifiedEnvelope]
    report: VerifiedEnvelope
    now_epoch_seconds: int = _NOW


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _accepted(raw: bytes, proposed: bytes, accepted: bytes) -> bytes:
    return raw.replace(proposed, accepted).replace(b"owner_acceptance_state`: `pending`", b"owner_acceptance_state`: `accepted`")


def _envelope(payload: object, schema_id: str, role: str, principal: Mapping[str, str]) -> VerifiedEnvelope:
    raw, verifier = valid_fixture_envelope()
    envelope = _fixture_envelope(payload)
    envelope.update(payload_schema_id=schema_id, payload_schema_sha256=_schema_digest(schema_id),
                    payload_sha256=_digest(payload), issuer_role=role, **{
                        "issuer_subject_id": principal["subject_id"],
                        "issuer_controlling_account_id": principal["controlling_account_id"],
                        "issuer_delegated_session_id": principal["delegated_session_id"],
                        "issuer_lane_id": principal["lane_id"],
                    })
    return verify_signed_envelope(_sign(envelope), _fixture_schema_store(), verifier, _NOW)


def _principals() -> dict[str, Mapping[str, str]]:
    registry = loads_canonical((ROOT / "scripts/rc0_policy/fixtures/platform_scope/v1/valid/fixture-adjunct-trust-schema-registry-v1.json").read_bytes())
    return {row["role_id"]: row["principal"] for row in registry["role_principal_constraints"]}


def _matrix() -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    scopes = [
        {"platform_scope_id": "linux-ubuntu-24_04-x86_64-production", "qualification_class": "production", "support_disposition": "supported", "os_family": "Ubuntu", "os_version": "24.04", "architecture": "x86_64", "required_gate_ids": ["fixture-production-test", "fixture-source-test"]},
        {"platform_scope_id": "macos-14-arm64-development-preview", "qualification_class": "development_preview", "support_disposition": "supported", "os_family": "macOS", "os_version": "14", "architecture": "arm64", "required_gate_ids": ["fixture-production-test", "fixture-source-test"]},
        {"platform_scope_id": "windows-11-24h2-x86_64-production", "qualification_class": "production", "support_disposition": "supported", "os_family": "Windows", "os_version": "11-24H2-client", "architecture": "x86_64", "required_gate_ids": ["fixture-production-test", "fixture-source-test"]},
    ]
    slots = [
        {"platform_scope_id": "linux-ubuntu-24_04-x86_64-production", "artifact_slot_id": "linux-appimage", "artifact_kind": "appimage"}, {"platform_scope_id": "linux-ubuntu-24_04-x86_64-production", "artifact_slot_id": "linux-deb", "artifact_kind": "deb"}, {"platform_scope_id": "macos-14-arm64-development-preview", "artifact_slot_id": "macos-app-development-adhoc", "artifact_kind": "macos_app_bundle"}, {"platform_scope_id": "macos-14-arm64-development-preview", "artifact_slot_id": "macos-dmg-development-adhoc", "artifact_kind": "dmg"}, {"platform_scope_id": "windows-11-24h2-x86_64-production", "artifact_slot_id": "windows-installer-unsigned", "artifact_kind": "msi"},
    ]
    inventory = loads_canonical((ROOT / "docs/profiles/opencode-baseline-inventory-v3.json").read_bytes())
    inventory_digest = hashlib.sha256(canonical_bytes(inventory)).hexdigest()
    inventory_items = inventory["digests"]["inventory_digest"].removeprefix("sha256:")
    schema_digest = inventory["digests"]["profile_schema_digest"].removeprefix("sha256:")
    opencode = hashlib.sha256(b"gocode.opencode-baseline-inventory-profile-binding/1\0" + canonical_bytes({"profile_id":"opencode-baseline-inventory","profile_revision":3,"inventory_payload_sha256":inventory_digest,"inventory_items_sha256":inventory_items,"profile_schema_sha256":schema_digest})).hexdigest()
    sources = (hashlib.sha256((ROOT / "contracts/gocode-ui-client-2/bundle.json").read_bytes()).hexdigest(), hashlib.sha256((ROOT / "docs/profiles/openai-responses-text-v1.json").read_bytes()).hexdigest(), opencode)
    profiles = []
    for scope in scopes:
        provider = "external_canary_only" if scope["platform_scope_id"].startswith("macos") else "required"
        for profile_id, revision, digest, state in (("gocode-local-runtime/2", 2, sources[0], "required"), ("gocode-openai-responses-text/1", 2, sources[1], provider), ("opencode-baseline-inventory", 3, sources[2], "required"), ("v1-rc0-no-local-tools/1", "v1-rc0-no-local-tools/1", None, "disabled_by_policy"), ("v1-rc0-no-production-mcp/1", "v1-rc0-no-production-mcp/1", None, "disabled_by_policy"), ("gocode-pty/1", "unavailable", None, "backend_unavailable")):
            profiles.append({"platform_scope_id": scope["platform_scope_id"], "profile_id": profile_id, "profile_revision": revision, "profile_sha256": digest, "state": state})
    return scopes, slots, sorted(profiles, key=lambda row: (row["platform_scope_id"], row["profile_id"]))


def _host_pins() -> list[dict[str, str]]:
    return [
        {"platform_scope_id": "linux-ubuntu-24_04-x86_64-production", "os_build": "fixture-ubuntu-24.04-build-1", "kernel_or_image_sha256": "1" * 64, "backend_id": "fixture-linux-backend", "backend_version": "1", "probe_set_payload_sha256": "2" * 64, "enforcement_descriptor_payload_sha256": "3" * 64},
        {"platform_scope_id": "macos-14-arm64-development-preview", "os_build": "fixture-macos-14-build-1", "kernel_or_image_sha256": "4" * 64, "backend_id": "fixture-macos-backend", "backend_version": "1", "probe_set_payload_sha256": "5" * 64, "enforcement_descriptor_payload_sha256": "6" * 64},
        {"platform_scope_id": "windows-11-24h2-x86_64-production", "os_build": "fixture-windows-11-24h2-build-1", "kernel_or_image_sha256": "7" * 64, "backend_id": "fixture-windows-backend", "backend_version": "1", "probe_set_payload_sha256": "8" * 64, "enforcement_descriptor_payload_sha256": "9" * 64},
    ]


def valid_mapping_fixture() -> MappingFixture:
    raw, verifier = valid_fixture_envelope()
    registry = verify_adjunct_trust_registry(verify_signed_envelope(raw, _fixture_schema_store(), verifier, _NOW), _fixture_schema_store(), "FIXTURE_ONLY", _NOW)
    principals = _principals()
    decision = canonical_bytes(loads_canonical(DECISION.read_bytes()))
    runtime = _accepted(RUNTIME_ADR.read_bytes(), b"**Status:** proposed", b"**Status:** accepted")
    desktop = _accepted(DESKTOP_ADR.read_bytes(), b"Proposed.", b"Accepted.")
    owner_rows = []
    for domain, adr_id, adr, role in (("runtime", "ADR-0027", runtime, "runtime_platform_owner"), ("desktop", "ADR-0015", desktop, "desktop_platform_owner")):
        owner_rows.append(_envelope({"schema_version": "gocode.governance.platform-decision-acceptance/1", "repository_id": "gocode", "owner_domain": domain, "owner_subject_id": principals[role]["subject_id"], "adr_id": adr_id, "adr_document_sha256": hashlib.sha256(adr).hexdigest(), "shared_decision_payload_sha256": hashlib.sha256(decision + b"\n").hexdigest(), "shared_decision_schema_sha256": hashlib.sha256((ROOT / "docs/schemas/v1-platform-scope-decision-v1.schema.json").read_bytes()).hexdigest(), "acceptance_revision": 1, "accepted_at": "2023-11-14T22:13:20Z"}, "gocode.governance.platform-decision-acceptance/1", role, principals[role]))
    scopes, slots, profiles = _matrix()
    claim = (VALID / "fixture-claim-migration-v1.json").read_bytes(); base = (VALID / "fixture-base-document-universe-v1.json").read_bytes(); delta = (VALID / "fixture-classified-delta-v1.json").read_bytes(); composed = (VALID / "fixture-composed-document-universe-v1.json").read_bytes()
    payload = {"schema_version": "gocode.rc0.platform-scope-mapping-policy/1", "repository_id": "gocode", "mapping_policy_revision": 1, "activation_epoch": 1, "predecessor_mapping_policy_envelope_sha256": None, "rc0_qualification_policy_digest": json.loads(POLICY.read_text())["policy_digest"], "shared_decision_payload_sha256": hashlib.sha256(decision + b"\n").hexdigest(), "shared_decision_schema_sha256": hashlib.sha256((ROOT / "docs/schemas/v1-platform-scope-decision-v1.schema.json").read_bytes()).hexdigest(), "runtime_adr_document_sha256": hashlib.sha256(runtime).hexdigest(), "desktop_adr_document_sha256": hashlib.sha256(desktop).hexdigest(), "runtime_owner_acceptance_envelope_sha256": owner_rows[0].envelope_sha256, "desktop_owner_acceptance_envelope_sha256": owner_rows[1].envelope_sha256, "adjunct_trust_registry_envelope_sha256": registry.envelope_sha256, "adjunct_trust_registry_payload_sha256": registry.payload_sha256, "claim_migration_registry_payload_sha256": hashlib.sha256(claim).hexdigest(), "claim_migration_registry_schema_sha256": _schema_digest("gocode.v1-platform-scope-claim-migration/1"), "base_document_universe_payload_sha256": hashlib.sha256(base).hexdigest(), "classified_delta_payload_sha256": hashlib.sha256(delta).hexdigest(), "composed_document_universe_payload_sha256": loads_canonical(composed)["composed_document_universe_payload_sha256"], "platform_scopes": scopes, "artifact_slot_mappings": slots, "profile_state_matrix": profiles, "host_identity_pins": _host_pins(), "attestation_payload_schema_sha256": _schema_digest("gocode.rc0.platform-scope-attestation/1"), "qualified_subject_payload_schema_sha256": _schema_digest("gocode.rc0.platform-qualified-subject/1"), "matrix_payload_schema_sha256": _schema_digest("gocode.release.platform-qualification-matrix/2")}
    envelope = _envelope(payload, "gocode.rc0.platform-scope-mapping-policy/1", "mapping_policy_authority", principals["mapping_policy_authority"])
    return MappingFixture(envelope, json.loads(POLICY.read_text()), decision, runtime, desktop, tuple(owner_rows), registry, claim, base, delta, composed)


def add_unknown_gate(value: MappingFixture) -> MappingFixture:
    return _mapping_mutation(value, "platform_scopes", lambda rows: rows.__setitem__(0, {**rows[0], "required_gate_ids": [*rows[0]["required_gate_ids"], "unknown"]}))


def remove_required_gate(value: MappingFixture) -> MappingFixture:
    return _mapping_mutation(value, "platform_scopes", lambda rows: rows.__setitem__(0, {**rows[0], "required_gate_ids": rows[0]["required_gate_ids"][1:]}))


def mix_rc0_policy_digest(value: MappingFixture) -> MappingFixture:
    return _mapping_mutation(value, "rc0_qualification_policy_digest", lambda payload: payload.__setitem__("rc0_qualification_policy_digest", "f" * 64))


def change_profile_state(value: MappingFixture) -> MappingFixture:
    return _mapping_mutation(value, "profile_state_matrix", lambda rows: rows.__setitem__(0, {**rows[0], "state": "disabled_by_policy"}))


def change_scope_slot_revision_or_null(value: MappingFixture, field: str) -> MappingFixture:
    mutations = {
        "scope": ("platform_scopes", lambda rows: rows.__setitem__(0, {**rows[0], "os_version": "99"})),
        "slot": ("artifact_slot_mappings", lambda rows: rows.__setitem__(0, {**rows[0], "platform_scope_id": "windows-11-24h2-x86_64-production"})),
        "revision": ("profile_state_matrix", lambda rows: rows.__setitem__(0, {**rows[0], "profile_revision": 99})),
        "null": ("profile_state_matrix", lambda rows: rows.__setitem__(0, {**rows[0], "profile_sha256": None})),
    }
    return _mapping_mutation(value, *mutations[field])


def _mapping_mutation(value: MappingFixture, field: str, mutate: object) -> MappingFixture:
    payload = loads_canonical(value.envelope.payload_canonical_bytes)
    target = payload[field]
    mutate(target) if isinstance(target, list) else mutate(payload)
    principal = _principals()["mapping_policy_authority"]
    changed = _envelope(payload, "gocode.rc0.platform-scope-mapping-policy/1", "mapping_policy_authority", principal)
    return MappingFixture(changed, value.rc0_policy, value.shared_decision_raw, value.runtime_adr_raw, value.desktop_adr_raw, value.owner_acceptances, value.adjunct_trust, value.claim_registry_raw, value.base_document_universe_raw, value.classified_delta_raw, value.composed_document_universe_raw)


def _projection(rows: list[dict[str, object]], artifact: bool) -> str:
    domain = b"gocode.rc0.exact-artifact-bindings-projection/1\0" if artifact else b"gocode.rc0.required-gate-results-projection/1\0"
    keys = ("relative_path", "sha256", "size", "locator") if artifact else ("gate_id", "stage", "execution_outcome", "gate_result", "blocked_reason", "binding")
    kept = [{key: row[key] for key in keys if key in row} for row in rows]
    kept.sort(key=canonical_bytes)
    return hashlib.sha256(domain + canonical_bytes(kept)).hexdigest()


def valid_declaration_fixture() -> DeclarationFixture:
    from scripts.rc0_policy.platform_policy import fixture_verify_mapping_policy

    fixture = valid_mapping_fixture(); mapping = fixture_verify_mapping_policy(**fixture.arguments())
    artifact = {"relative_path": "dist/gocode.tar", "sha256": "f" * 64, "size": 3, "locator": "cas:sha256:" + "f" * 64}
    binding = {"repository_id": "gocode", "candidate_source_sha": "a" * 40, "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000", "observed_evidence_revision": "b" * 40, "evidence_bundle_digest": "d" * 64, "policy_revision": 3, "policy_digest": mapping.rc0_qualification_policy_digest, "profile": "gocode.rc0.evidence-profile/3", "exact_artifact_bindings": [artifact]}
    gates = [{"gate_id": gate, "stage": stage, "execution_outcome": "PASS", "gate_result": "PASS", "binding": dict(binding)} for gate, stage in (("fixture-source-test", "SOURCE_CANDIDATE"), ("fixture-production-test", "PRODUCTION_QUALIFICATION"))]
    report_payload = {**binding, "schema_id": "gocode.rc0.schema.verification-report/3", "required_gate_results": gates, "source_candidate_gate": {"gate_result": "PASS"}, "production_qualification_gate": {"gate_result": "PASS"}, "evidence_seal_gate": {"gate_result": "PASS"}, "overall_candidate_gate": {"gate_result": "PASS"}, "stage_dispositions": [{"stage": "RELEASE_APPROVAL", "report_stage_disposition": "OUT_OF_SCOPE"}, {"stage": "PUBLICATION_AUTHORIZATION", "report_stage_disposition": "OUT_OF_SCOPE"}], "runner_identity": {"runner_class": "fixture", "executable_digest": "e" * 64}, "issued_at": "2026-08-09T00:00:00.000000Z"}
    schemas = _fixture_schema_store(); documents = dict(schemas._schemas); schema_id = "gocode.rc0.schema.verification-report/3"; documents[schema_id] = (ROOT / "docs/schemas/rc0-verification-report-v3.schema.json").read_bytes(); report_store = AdjunctSchemaStore(documents)
    principals = _principals(); report_raw = _sign({**_fixture_envelope(report_payload), "payload_schema_id": schema_id, "payload_schema_sha256": hashlib.sha256(documents[schema_id]).hexdigest(), "payload_sha256": _digest(report_payload), "issuer_role": "rc0_qualification_reporter", "issuer_subject_id": principals["rc0_qualification_reporter"]["subject_id"], "issuer_controlling_account_id": principals["rc0_qualification_reporter"]["controlling_account_id"], "issuer_delegated_session_id": principals["rc0_qualification_reporter"]["delegated_session_id"], "issuer_lane_id": principals["rc0_qualification_reporter"]["lane_id"]})
    _, verifier = valid_fixture_envelope(); report = verify_signed_envelope(report_raw, report_store, verifier, _NOW)
    declaration_payload = {"schema_version": "gocode.rc0.qualified-declaration/1", "repository_id": "gocode", "declaration_state": "RC0_QUALIFIED", "common_binding_group": binding, "common_binding_group_payload_sha256": _digest(binding), "rc0_qualification_policy_digest": mapping.rc0_qualification_policy_digest, "verification_report_envelope_sha256": report.envelope_sha256, "required_gate_set_payload_sha256": _projection(gates, False), "artifact_set_payload_sha256": _projection([artifact], True), "runner_lane_id": principals["rc0_qualification_declarer"]["lane_id"]}
    declaration = _envelope(declaration_payload, "gocode.rc0.qualified-declaration/1", "rc0_qualification_declarer", principals["rc0_qualification_declarer"])
    return DeclarationFixture(declaration, fixture.rc0_policy, mapping, lambda digest: report_raw if digest == report.envelope_sha256 else b"", lambda raw: verify_signed_envelope(raw, report_store, verifier, _NOW), report)


def replace_declaration_field(value: VerifiedEnvelope, field: str, replacement: object) -> VerifiedEnvelope:
    payload = loads_canonical(value.payload_canonical_bytes); payload[field] = replacement
    return _envelope(payload, "gocode.rc0.qualified-declaration/1", "rc0_qualification_declarer", _principals()["rc0_qualification_declarer"])
