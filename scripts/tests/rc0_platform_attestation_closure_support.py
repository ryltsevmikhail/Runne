"""Fixture builders for structural artifact-closure tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, VerifiedEnvelope, verify_signed_envelope
from scripts.tests.rc0_platform_envelope_support import (
    _NOW, _fixture_envelope, _fixture_schema_store, _schema_digest, _sign,
    valid_fixture_envelope,
)


__all__ = ("ClosureFixture", "replace_host_payload", "replace_host_profile", "replace_measurement_identity", "replace_measurement_payload", "replace_measurement_profile", "valid_closure_fixture")

_MEASUREMENT = "gocode.rc0.artifact-measurement-record/1"
_HOST = "gocode.rc0.native-host-evidence-record/1"
_COMMON = {
    "repository_id": "gocode", "candidate_source_sha": "a" * 40,
    "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
    "observed_evidence_revision": "b" * 40, "evidence_bundle_digest": "d" * 64,
    "policy_revision": 3, "policy_digest": "4" * 64,
    "profile": "gocode.rc0.evidence-profile/3",
    "exact_artifact_bindings": [{"relative_path": "dist/gocode.tar", "sha256": "f" * 64,
        "size": 3, "locator": "cas:sha256:" + "f" * 64}],
}
_SLOTS = {
    "linux-appimage": ("linux-ubuntu-24_04-x86_64-production", "appimage"),
    "linux-deb": ("linux-ubuntu-24_04-x86_64-production", "deb"),
    "windows-installer-unsigned": ("windows-11-24h2-x86_64-production", "msi"),
    "macos-app-development-adhoc": ("macos-14-arm64-development-preview", "macos_app_bundle"),
    "macos-dmg-development-adhoc": ("macos-14-arm64-development-preview", "dmg"),
}
_INVENTORIES = {
    scope: tuple(sorted((item, kind) for item, (candidate, kind) in _SLOTS.items() if candidate == scope))
    for scope in {scope for scope, _ in _SLOTS.values()}
}
_CONTROLS = (
    "linux_protected_transport", "linux_landlock", "linux_seccomp", "linux_cgroups_v2",
    "linux_descendant_cleanup", "linux_direct_egress_denial", "windows_owner_acl",
    "windows_owner_dacl", "windows_reparse_safe", "windows_appcontainer",
    "windows_job_object_cleanup", "windows_descendant_cleanup", "windows_direct_egress_denial",
    "macos_protected_transport", "macos_cleanup", "macos_direct_egress_denial",
    "macos_no_login_keychain", "macos_no_ssh_material", "macos_no_workspace",
    "macos_no_credential_environment", "macos_no_inherited_handles",
)


@dataclass(frozen=True)
class ClosureFixture:
    measurement_a: VerifiedEnvelope
    measurement_b: VerifiedEnvelope
    host_record: VerifiedEnvelope


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _envelope(payload: object, schema_id: str, role: str, lane: str) -> VerifiedEnvelope:
    _, verifier = valid_fixture_envelope()
    outer = _fixture_envelope(payload)
    outer.update(
        payload_schema_id=schema_id, payload_schema_sha256=_schema_digest(schema_id),
        payload_sha256=_digest(payload), issuer_role=role,
        issuer_subject_id=f"{lane}-subject", issuer_controlling_account_id=f"{lane}-account",
        issuer_delegated_session_id=f"{lane}-session", issuer_lane_id=lane,
    )
    return verify_signed_envelope(_sign(outer), _fixture_schema_store(), verifier, _NOW)


def _manifest(slot: str, kind: str, raw: Mapping[str, object]) -> dict[str, object]:
    platform = "linux_product_payload" if slot.startswith("linux") else (
        "windows_helper" if slot.startswith("windows") else "macos_app_dmg"
    )
    shapes = {name: "PASS" for name in (
        "path_normalization", "traversal", "symlink", "hardlink", "special_file",
        "case_collision", "unlisted_package_script",
    )}
    shapes.update({name: "PASS" if name == platform else "NOT_APPLICABLE" for name in (
        "linux_product_payload", "windows_helper", "macos_app_dmg",
    )})
    return {
        "schema_version": "gocode.rc0.artifact-manifest-payload/1", "artifact_slot_id": slot,
        "artifact_kind": kind, "raw_artifact": dict(raw),
        "entries": [{"relative_path": "bin/gocode", "sha256": "c" * 64, "size": 1,
                     "mode": "0755", "executable_architecture": "x86_64",
                     "entitlement_capability_descriptor_sha256": "d" * 64, "role": "product"}],
        "shape_results": shapes,
    }


def _measurement(slot: str, kind: str, scope: str, raw: Mapping[str, object], manifest: Mapping[str, object], lane: str, role: str) -> VerifiedEnvelope:
    artifact_manifest = _digest(manifest)
    payload = {
        "schema_version": _MEASUREMENT, "repository_id": "gocode",
        "mapping_policy_envelope_sha256": "1" * 64, "adjunct_trust_registry_envelope_sha256": "2" * 64,
        "adjunct_trust_registry_payload_sha256": "3" * 64, "rc0_qualification_policy_digest": "4" * 64,
        "active_activation_snapshot_envelope_sha256": "5" * 64, "common_binding_group": dict(_COMMON),
        "common_binding_group_payload_sha256": _digest(_COMMON), "platform_scope_id": scope,
        "artifact_slot_id": slot, "artifact_kind": kind, "relative_path": raw["relative_path"],
        "artifact_sha256": raw["sha256"], "size": raw["size"], "locator": raw["locator"],
        "artifact_manifest_payload": dict(manifest), "artifact_manifest_payload_sha256": artifact_manifest,
        "product_manifest_payload_sha256": "6" * 64,
        "classifier_implementation_sha256": ("7" if lane.endswith("a") else "8") * 64,
        "classifier_dependency_set_sha256": ("9" if lane.endswith("a") else "a") * 64,
        "classifier_lane_id": lane, "classifier_run_id": f"{lane}-run",
        "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:25Z",
    }
    return _envelope(payload, _MEASUREMENT, role, lane)


def _host(slot: str, kind: str, scope: str, raw: Mapping[str, object], artifact_manifest: str) -> VerifiedEnvelope:
    family, version, architecture = ("Ubuntu", "24.04", "x86_64") if slot.startswith("linux") else (
        ("Windows", "11-24H2-client", "x86_64") if slot.startswith("windows") else ("macOS", "14", "arm64")
    )
    platform = family.lower() if family != "macOS" else "macos"
    executed = []
    for item, item_kind in _INVENTORIES[scope]:
        item_raw = raw if item == slot else {"relative_path": f"dist/{item}", "sha256": hashlib.sha256(item.encode()).hexdigest(), "size": 3, "locator": "cas:sha256:" + hashlib.sha256(item.encode()).hexdigest()}
        item_manifest = artifact_manifest if item == slot else _digest(_manifest(item, item_kind, item_raw))
        executed.append({"artifact_slot_id": item, "artifact_kind": item_kind, **item_raw,
                         "artifact_manifest_payload_sha256": item_manifest, "product_manifest_payload_sha256": "6" * 64})
    controls = [{"control_id": name, "result": "PASS" if name.startswith(platform) else "NOT_APPLICABLE"} for name in _CONTROLS]
    payload = {
        "schema_version": _HOST, "repository_id": "gocode", "mapping_policy_envelope_sha256": "1" * 64,
        "adjunct_trust_registry_envelope_sha256": "2" * 64, "adjunct_trust_registry_payload_sha256": "3" * 64,
        "rc0_qualification_policy_digest": "4" * 64, "active_activation_snapshot_envelope_sha256": "5" * 64,
        "common_binding_group": dict(_COMMON), "common_binding_group_payload_sha256": _digest(_COMMON),
        "platform_scope_id": scope, "os_family": family, "os_version": version, "os_build": "fixture-build",
        "kernel_or_image_sha256": "e" * 64, "architecture": architecture, "native_mode": "native",
        "backend_id": "fixture-backend", "backend_version": "1", "probe_set_payload_sha256": "f" * 64,
        "enforcement_descriptor_payload_sha256": "0" * 64, "workflow_run_id": "host-run",
        "executed_artifacts": executed, "control_results": controls,
        "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:25Z",
    }
    return _envelope(payload, _HOST, "native_host_attestor", "host-lane")


def valid_closure_fixture(slot: str) -> ClosureFixture:
    scope, kind = _SLOTS[slot]
    raw = {"relative_path": f"dist/{slot}", "sha256": "b" * 64, "size": 3, "locator": "cas:sha256:" + "b" * 64}
    manifest = _manifest(slot, kind, raw)
    first = _measurement(slot, kind, scope, raw, manifest, "classifier-a", "artifact_classifier_a")
    second = _measurement(slot, kind, scope, raw, manifest, "classifier-b", "artifact_classifier_b")
    return ClosureFixture(first, second, _host(slot, kind, scope, raw, _digest(manifest)))


def replace_measurement_payload(value: VerifiedEnvelope, **changes: object) -> VerifiedEnvelope:
    payload = loads_canonical(value.payload_canonical_bytes)
    payload.update(changes)
    return _envelope(payload, _MEASUREMENT, value.issuer_role, value.issuer_lane_id)


def replace_measurement_identity(value: VerifiedEnvelope, **changes: object) -> VerifiedEnvelope:
    outer = loads_canonical(value.envelope_canonical_bytes)
    outer.update(changes)
    _, verifier = valid_fixture_envelope()
    return verify_signed_envelope(_sign(outer), _fixture_schema_store(), verifier, _NOW)


def _replace_profile(value: VerifiedEnvelope, schema_id: str, profile: str) -> VerifiedEnvelope:
    payload = loads_canonical(value.payload_canonical_bytes)
    payload["common_binding_group"]["profile"] = profile
    payload["common_binding_group_payload_sha256"] = _digest(payload["common_binding_group"])
    schemas = dict(_fixture_schema_store()._schemas)
    schema = loads_canonical(schemas[schema_id])
    schema["$defs"]["common"]["properties"]["profile"] = {"type": "string", "minLength": 1, "maxLength": 4096}
    schemas[schema_id] = canonical_bytes(schema)
    outer = _fixture_envelope(payload)
    outer.update(payload_schema_id=schema_id, payload_schema_sha256=hashlib.sha256(schemas[schema_id]).hexdigest(), payload_sha256=_digest(payload), issuer_role=value.issuer_role, issuer_subject_id=value.issuer_subject_id, issuer_controlling_account_id=value.issuer_controlling_account_id, issuer_delegated_session_id=value.issuer_delegated_session_id, issuer_lane_id=value.issuer_lane_id)
    _, verifier = valid_fixture_envelope()
    return verify_signed_envelope(_sign(outer), AdjunctSchemaStore(schemas), verifier, _NOW)


def replace_measurement_profile(value: VerifiedEnvelope, profile: str) -> VerifiedEnvelope:
    return _replace_profile(value, _MEASUREMENT, profile)


def replace_host_profile(value: VerifiedEnvelope, profile: str) -> VerifiedEnvelope:
    return _replace_profile(value, _HOST, profile)


def replace_host_payload(value: VerifiedEnvelope, **changes: object) -> VerifiedEnvelope:
    payload = loads_canonical(value.payload_canonical_bytes)
    payload.update(changes)
    return _envelope(payload, _HOST, value.issuer_role, value.issuer_lane_id)
