"""Strict adjunct-schema document and instance validation tests."""

from __future__ import annotations

import unittest
from copy import deepcopy

from scripts.rc0_policy.adjunct_schema_validation import (
    AdjunctSchemaValidationError, parse_adjunct_schema, validate_adjunct_schema_instance,
)
from scripts.rc0_policy.canonical import canonical_bytes
from scripts.tests.rc0_platform_envelope_support import _schema_documents


_SHA = "a" * 64
_LOCATOR = f"cas:sha256:{_SHA}"
_COMMON = {
    "repository_id": "gocode", "candidate_source_sha": "b" * 40,
    "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
    "observed_evidence_revision": "c" * 40, "evidence_bundle_digest": _SHA,
    "policy_revision": 3, "policy_digest": _SHA, "profile": "gocode.rc0.evidence-profile/3",
    "exact_artifact_bindings": [{"relative_path": "artifact", "sha256": _SHA,
        "size": 0, "locator": _LOCATOR}],
}
_LINEAGE = {
    "repository_id": "gocode", "mapping_policy_envelope_sha256": _SHA,
    "adjunct_trust_registry_envelope_sha256": _SHA,
    "adjunct_trust_registry_payload_sha256": _SHA,
    "rc0_qualification_policy_digest": _SHA,
    "active_activation_snapshot_envelope_sha256": _SHA,
    "common_binding_group": _COMMON,
    "common_binding_group_payload_sha256": _SHA,
    "platform_scope_id": "linux-ubuntu-24_04-x86_64-production",
}
_SHAPES = (
    "path_normalization", "traversal", "symlink", "hardlink", "special_file",
    "case_collision", "unlisted_package_script", "linux_product_payload",
    "windows_helper", "macos_app_dmg",
)
_CONTROLS = (
    "linux_protected_transport", "linux_landlock", "linux_seccomp", "linux_cgroups_v2",
    "linux_descendant_cleanup", "linux_direct_egress_denial", "windows_owner_acl",
    "windows_owner_dacl", "windows_reparse_safe", "windows_appcontainer",
    "windows_job_object_cleanup", "windows_descendant_cleanup", "windows_direct_egress_denial",
    "macos_protected_transport", "macos_cleanup", "macos_direct_egress_denial",
    "macos_no_login_keychain", "macos_no_ssh_material", "macos_no_workspace",
    "macos_no_credential_environment", "macos_no_inherited_handles",
)


def _schema(schema_id: str) -> dict[str, object]:
    return parse_adjunct_schema(_schema_documents()[schema_id], schema_id)


def _artifact() -> dict[str, object]:
    return {
        "relative_path": "artifact", "sha256": _SHA, "size": 0,
        "locator": _LOCATOR, "artifact_manifest_payload_sha256": _SHA,
        "product_manifest_payload_sha256": _SHA,
    }


def _manifest() -> dict[str, object]:
    return {
        "schema_version": "gocode.rc0.artifact-manifest-payload/1",
        "artifact_slot_id": "linux-appimage", "artifact_kind": "appimage",
        "raw_artifact": {key: _artifact()[key] for key in ("relative_path", "sha256", "size", "locator")},
        "entries": [{"relative_path": "app", "sha256": _SHA, "size": 0, "mode": "0755", "executable_architecture": "x86_64", "entitlement_capability_descriptor_sha256": _SHA, "role": "application"}],
        "shape_results": {name: "PASS" if name != "windows_helper" and name != "macos_app_dmg" else "NOT_APPLICABLE" for name in _SHAPES},
    }


class AdjunctSchemaValidationTests(unittest.TestCase):
    def test_accepts_all_nineteen_provisioned_schema_documents(self) -> None:
        for schema_id, raw in _schema_documents().items():
            with self.subTest(schema_id=schema_id):
                self.assertEqual(parse_adjunct_schema(raw, schema_id)["$id"], schema_id)

    def test_validates_supported_instance_keywords(self) -> None:
        schema = {
            "$id": "test/1", "type": "object", "additionalProperties": False,
            "required": ["kind", "tags", "count"], "maxProperties": 3,
            "properties": {
                "kind": {"anyOf": [{"const": "one"}, {"enum": ["two"]}]},
                "tags": {"type": "array", "minItems": 1, "maxItems": 2, "uniqueItems": True, "items": {"type": "string", "minLength": 1, "maxLength": 3, "pattern": "^[a-z]+$"}},
                "count": {"type": "integer", "minimum": 1, "maximum": 2},
            },
        }
        self.assertEqual(validate_adjunct_schema_instance(schema, {"kind": "one", "tags": ["a"], "count": 1}), ())
        self.assertTrue(validate_adjunct_schema_instance(schema, {"kind": "bad", "tags": ["a", "a"], "count": 0, "extra": 1}))

    def test_anyof_and_local_reference_siblings_are_conjunctive(self) -> None:
        anyof = {"type": "integer", "anyOf": [{"const": "x"}]}
        reference = {
            "$defs": {"constant": {"const": "x"}}, "$ref": "#/$defs/constant",
            "type": "integer",
        }
        self.assertTrue(validate_adjunct_schema_instance(anyof, "x"))
        self.assertTrue(validate_adjunct_schema_instance(reference, "x"))

    def test_rejects_unsupported_missing_external_and_cyclic_schema_references(self) -> None:
        vectors = (
            {"$id": "test/1", "type": "array", "minItemsTypo": 1},
            {"$id": "test/1", "$ref": "https://example.invalid/schema"},
            {"$id": "test/1", "$ref": "#/$defs/missing"},
            {"$id": "test/1", "$defs": {"loop": {"$ref": "#/$defs/loop"}}, "$ref": "#/$defs/loop"},
        )
        for value in vectors:
            with self.subTest(value=value):
                with self.assertRaises(AdjunctSchemaValidationError):
                    parse_adjunct_schema(canonical_bytes(value), "test/1")

    def test_rejects_malformed_root_and_nested_schema_keywords(self) -> None:
        root = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "test/1", "title": "test"}
        vectors = (
            {**root, "$schema": 1},
            {**root, "properties": {"value": {"minItemsTypo": 1}}},
            {**root, "type": []},
            {**root, "items": {"type": "string"}, "minItems": -1},
            {**root, "enum": [1, 1]},
        )
        for value in vectors:
            with self.subTest(value=value):
                with self.assertRaises(AdjunctSchemaValidationError):
                    parse_adjunct_schema(canonical_bytes(value), "test/1")

    def test_task_six_nested_contract_projections_are_closed(self) -> None:
        measurement = {
            **_LINEAGE, "schema_version": "gocode.rc0.artifact-measurement-record/1",
            "artifact_slot_id": "linux-appimage", "artifact_kind": "appimage",
            "relative_path": "artifact", "artifact_sha256": _SHA, "size": 0,
            "locator": _LOCATOR, "artifact_manifest_payload": _manifest(),
            "artifact_manifest_payload_sha256": _SHA, "product_manifest_payload_sha256": _SHA,
            "classifier_implementation_sha256": _SHA, "classifier_dependency_set_sha256": _SHA,
            "classifier_lane_id": "classifier", "classifier_run_id": "run",
            "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z",
        }
        host = {
            **_LINEAGE, "schema_version": "gocode.rc0.native-host-evidence-record/1",
            "os_family": "Ubuntu", "os_version": "24.04", "os_build": "build",
            "kernel_or_image_sha256": _SHA, "architecture": "x86_64", "native_mode": "native",
            "backend_id": "backend", "backend_version": "1", "probe_set_payload_sha256": _SHA,
            "enforcement_descriptor_payload_sha256": _SHA, "workflow_run_id": "run",
            "executed_artifacts": [{**_artifact(), "artifact_slot_id": "linux-appimage", "artifact_kind": "appimage"}],
            "control_results": [{"control_id": control, "result": "PASS" if control.startswith("linux_") else "NOT_APPLICABLE"} for control in _CONTROLS],
            "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z",
        }
        profile = {
            **_LINEAGE, "schema_version": "gocode.rc0.profile-evidence-record/1",
            "profile_id": "profile", "profile_revision": 1, "profile_sha256": None,
            "state": "disabled_by_policy", "canonical_result": "DISABLED_BY_POLICY",
            "artifact_slot_ids": ["linux-appimage"], "rc0_gate_evidence_sha256s": [_SHA],
            "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z",
        }
        canary = {
            **{**_LINEAGE, "platform_scope_id": "macos-14-arm64-development-preview"},
            "schema_version": "gocode.rc0.canary-evidence-record/1",
            "profile_id": "gocode-openai-responses-text/1", "profile_revision": 1,
            "profile_sha256": _SHA, "state": "external_canary_only",
            "artifact_slot_ids": ["macos-app-development-adhoc"], "rc0_gate_evidence_sha256s": [_SHA],
            "operator_lane_id": "operator", "canonical_result": "PASS",
            "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z",
        }
        attestation = {
            **_LINEAGE, "schema_version": "gocode.rc0.platform-scope-attestation/1",
            "qualification_class": "production", "artifact_measurements": [_SHA, "b" * 64],
            "host_evidence_records": [_SHA], "profile_evidence_records": [_SHA],
            "canary_evidence_records": [], "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z", "producing_lane_id": "aggregate",
        }
        vectors = {
            "gocode.rc0.artifact-measurement-record/1": measurement,
            "gocode.rc0.native-host-evidence-record/1": host,
            "gocode.rc0.profile-evidence-record/1": profile,
            "gocode.rc0.canary-evidence-record/1": canary,
            "gocode.rc0.platform-scope-attestation/1": attestation,
        }
        for schema_id, vector in vectors.items():
            with self.subTest(schema_id=schema_id):
                self.assertEqual(validate_adjunct_schema_instance(_schema(schema_id), vector), ())
        for schema_id, vector in (
            ("gocode.rc0.artifact-measurement-record/1", measurement),
            ("gocode.rc0.native-host-evidence-record/1", host),
            ("gocode.rc0.profile-evidence-record/1", profile),
            ("gocode.rc0.canary-evidence-record/1", canary),
        ):
            microseconds = deepcopy(vector)
            microseconds["observed_at"] = "2023-11-14T22:13:20.123456Z"
            microseconds["freshness_deadline"] = "2023-11-14T22:13:30.123456Z"
            with self.subTest(schema_id=schema_id, form="microsecond"):
                self.assertEqual(validate_adjunct_schema_instance(_schema(schema_id), microseconds), ())

    def test_task_six_schema_closure_rejects_one_field_mutations(self) -> None:
        measurement = {
            **_LINEAGE, "schema_version": "gocode.rc0.artifact-measurement-record/1",
            "artifact_slot_id": "linux-appimage", "artifact_kind": "appimage",
            "relative_path": "artifact", "artifact_sha256": _SHA, "size": 0,
            "locator": _LOCATOR, "artifact_manifest_payload": _manifest(),
            "artifact_manifest_payload_sha256": _SHA, "product_manifest_payload_sha256": _SHA,
            "classifier_implementation_sha256": _SHA, "classifier_dependency_set_sha256": _SHA,
            "classifier_lane_id": "classifier", "classifier_run_id": "run",
            "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z",
        }
        host = {
            **_LINEAGE, "schema_version": "gocode.rc0.native-host-evidence-record/1",
            "os_family": "Ubuntu", "os_version": "24.04", "os_build": "build",
            "kernel_or_image_sha256": _SHA, "architecture": "x86_64", "native_mode": "native",
            "backend_id": "backend", "backend_version": "1", "probe_set_payload_sha256": _SHA,
            "enforcement_descriptor_payload_sha256": _SHA, "workflow_run_id": "run",
            "executed_artifacts": [{**_artifact(), "artifact_slot_id": "linux-appimage", "artifact_kind": "appimage"}],
            "control_results": [{"control_id": control, "result": "PASS" if control.startswith("linux_") else "NOT_APPLICABLE"} for control in _CONTROLS],
            "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z",
        }
        profile = {
            **_LINEAGE, "schema_version": "gocode.rc0.profile-evidence-record/1",
            "profile_id": "profile", "profile_revision": 1, "profile_sha256": None,
            "state": "disabled_by_policy", "canonical_result": "DISABLED_BY_POLICY",
            "artifact_slot_ids": ["linux-appimage"], "rc0_gate_evidence_sha256s": [_SHA],
            "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z",
        }
        canary = {
            **{**_LINEAGE, "platform_scope_id": "macos-14-arm64-development-preview"},
            "schema_version": "gocode.rc0.canary-evidence-record/1",
            "profile_id": "gocode-openai-responses-text/1", "profile_revision": 1,
            "profile_sha256": _SHA, "state": "external_canary_only",
            "artifact_slot_ids": ["macos-app-development-adhoc"], "rc0_gate_evidence_sha256s": [_SHA],
            "operator_lane_id": "operator", "canonical_result": "PASS",
            "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z",
        }
        attestation = {
            **_LINEAGE, "schema_version": "gocode.rc0.platform-scope-attestation/1",
            "qualification_class": "production", "artifact_measurements": [_SHA, "b" * 64],
            "host_evidence_records": [_SHA], "profile_evidence_records": [_SHA],
            "canary_evidence_records": [], "observed_at": "2023-11-14T22:13:20Z", "freshness_deadline": "2023-11-14T22:13:30Z", "producing_lane_id": "aggregate",
        }
        bad_manifest_extra = deepcopy(measurement); bad_manifest_extra["artifact_manifest_payload"]["extra"] = 1
        bad_manifest_missing = deepcopy(measurement); del bad_manifest_missing["artifact_manifest_payload"]["shape_results"]["hardlink"]
        bad_host_slot = deepcopy(host); del bad_host_slot["executed_artifacts"][0]["artifact_slot_id"]
        bad_host_kind = deepcopy(host); del bad_host_kind["executed_artifacts"][0]["artifact_kind"]
        bad_host_control = deepcopy(host); bad_host_control["control_results"][0]["extra"] = 1
        bad_profile_result = deepcopy(profile); bad_profile_result["canonical_result"] = "FAILED"
        bad_canary_result = deepcopy(canary); bad_canary_result["canonical_result"] = "FAILED"
        bad_canary_disabled = deepcopy(canary); bad_canary_disabled["canonical_result"] = "DISABLED_BY_POLICY"
        bad_canary_unavailable = deepcopy(canary); bad_canary_unavailable["canonical_result"] = "BackendUnavailable"
        bad_attestation_lineage = deepcopy(attestation); bad_attestation_lineage["mapping_policy_envelope_sha256"] += "\n"
        bad_measurement_digest = deepcopy(measurement); bad_measurement_digest["artifact_sha256"] += "\n"
        bad_measurement_locator = deepcopy(measurement); bad_measurement_locator["locator"] += "\n"
        bad_host_digest = deepcopy(host); bad_host_digest["kernel_or_image_sha256"] += "\n"
        bad_host_locator = deepcopy(host); bad_host_locator["executed_artifacts"][0]["locator"] += "\n"
        bad_profile_digest = deepcopy(profile); bad_profile_digest["rc0_gate_evidence_sha256s"][0] += "\n"
        bad_canary_digest = deepcopy(canary); bad_canary_digest["profile_sha256"] += "\n"
        bad_attestation_canary = deepcopy(attestation); del bad_attestation_canary["canary_evidence_records"]
        candidate_sha_vectors = []
        for schema_id, value in (("gocode.rc0.artifact-measurement-record/1", measurement), ("gocode.rc0.native-host-evidence-record/1", host), ("gocode.rc0.profile-evidence-record/1", profile), ("gocode.rc0.canary-evidence-record/1", canary), ("gocode.rc0.platform-scope-attestation/1", attestation)):
            bad = deepcopy(value); bad["common_binding_group"]["candidate_source_sha"] += "\n"; candidate_sha_vectors.append((schema_id, bad))
        timestamp_vectors = []
        for schema_id, value in (("gocode.rc0.artifact-measurement-record/1", measurement), ("gocode.rc0.native-host-evidence-record/1", host), ("gocode.rc0.profile-evidence-record/1", profile), ("gocode.rc0.canary-evidence-record/1", canary)):
            for field in ("observed_at", "freshness_deadline"):
                bad = deepcopy(value); bad[field] += "\n"; timestamp_vectors.append((schema_id, bad))
        vectors = (
            ("gocode.rc0.artifact-measurement-record/1", bad_manifest_extra),
            ("gocode.rc0.artifact-measurement-record/1", bad_manifest_missing),
            ("gocode.rc0.native-host-evidence-record/1", bad_host_slot),
            ("gocode.rc0.native-host-evidence-record/1", bad_host_kind),
            ("gocode.rc0.native-host-evidence-record/1", bad_host_control),
            ("gocode.rc0.profile-evidence-record/1", bad_profile_result),
            ("gocode.rc0.canary-evidence-record/1", bad_canary_result),
            ("gocode.rc0.canary-evidence-record/1", bad_canary_disabled),
            ("gocode.rc0.canary-evidence-record/1", bad_canary_unavailable),
            ("gocode.rc0.platform-scope-attestation/1", bad_attestation_lineage),
            ("gocode.rc0.artifact-measurement-record/1", bad_measurement_digest),
            ("gocode.rc0.artifact-measurement-record/1", bad_measurement_locator),
            ("gocode.rc0.native-host-evidence-record/1", bad_host_digest),
            ("gocode.rc0.native-host-evidence-record/1", bad_host_locator),
            ("gocode.rc0.profile-evidence-record/1", bad_profile_digest),
            ("gocode.rc0.canary-evidence-record/1", bad_canary_digest),
            ("gocode.rc0.platform-scope-attestation/1", bad_attestation_canary),
        ) + tuple(candidate_sha_vectors) + tuple(timestamp_vectors)
        for schema_id, vector in vectors:
            with self.subTest(schema_id=schema_id, vector=vector):
                self.assertTrue(validate_adjunct_schema_instance(_schema(schema_id), vector))

    def test_six_common_binding_schemas_reject_missing_and_extra_fields(self) -> None:
        schema_ids = ("gocode.rc0.qualified-declaration/1", "gocode.rc0.platform-scope-attestation/1", "gocode.rc0.artifact-measurement-record/1", "gocode.rc0.native-host-evidence-record/1", "gocode.rc0.profile-evidence-record/1", "gocode.rc0.canary-evidence-record/1")
        for schema_id in schema_ids:
            schema = _schema(schema_id); key = "common_binding_group" if schema_id.endswith("qualified-declaration/1") else "common"
            common_schema = {"$defs": schema["$defs"], **schema["$defs"][key]}
            missing = deepcopy(_COMMON); missing.pop("observed_evidence_revision")
            extra = {**_COMMON, "unexpected": "closed"}
            with self.subTest(schema_id=schema_id, vector="valid"):
                self.assertEqual(validate_adjunct_schema_instance(common_schema, _COMMON), ())
            for name, value in (("missing", missing), ("extra", extra)):
                with self.subTest(schema_id=schema_id, vector=name):
                    self.assertTrue(validate_adjunct_schema_instance(common_schema, value))


if __name__ == "__main__":
    unittest.main()
