import json
import pathlib
import unittest
from copy import deepcopy

from scripts.tests.test_project_owner_authority_schemas import _errors


ROOT = pathlib.Path(__file__).parents[2]
SCHEMAS = {
    "release-rc1-qualification-decision-v1.schema.json": "gocode.release.rc1-qualification-decision/1",
    "unsigned-candidate-manifest-v1.schema.json": "gocode.release.unsigned-candidate-manifest/1",
    "release-rc2-signed-artifact-record-v2.schema.json": "gocode.release.rc2-signed-artifact-record/2",
    "release-rc2-threshold-update-metadata-set-v2.schema.json": "gocode.release.rc2-threshold-update-metadata-set/2",
    "rc2-signing-authorization-v1.schema.json": "gocode.release.rc2-signing-authorization/1",
    "rc2-signing-effect-claim-v1.schema.json": "gocode.release.rc2-signing-effect-claim/1",
    "rc2-native-evidence-v1.schema.json": "gocode.release.rc2-native-evidence/1",
    "rc2-signing-review-v1.schema.json": "gocode.release.rc2-signing-review/1",
    "rc2-update-metadata-issuance-v1.schema.json": "gocode.release.rc2-update-metadata-issuance/1",
    "signed-envelope-inventory-v1.schema.json": "gocode.release.signed-envelope-inventory/1",
    "signed-envelope-verification-report-v1.schema.json": "gocode.release.signed-envelope-verification-report/1",
    "rc3-publication-authorization-v1.schema.json": "gocode.release.rc3-publication-authorization/1",
    "publication-manifest-v1.schema.json": "gocode.release.publication-manifest/1",
    "promotion-state-snapshot-v1.schema.json": "gocode.release.promotion-state-snapshot/1",
    "publication-effect-intent-v1.schema.json": "gocode.release.publication-effect-intent/1",
    "publication-effect-settlement-v1.schema.json": "gocode.release.publication-effect-settlement/1",
    "publication-effect-ledger-v1.schema.json": "gocode.release.publication-effect-ledger/1",
}


class ReleaseAuthoritySchemaParityTests(unittest.TestCase):
    def test_shared_stage_identifier_corpus_is_rejected_by_rc1_and_rc3_schemas(self) -> None:
        corpus = json.loads(
            (ROOT / "crates/gocode-promotion-contracts/tests/fixtures/stage_identifier_corpus.json")
            .read_text(encoding="utf-8")
        )
        rc1 = json.loads((ROOT / "docs/schemas/release-rc1-qualification-decision-v1.schema.json").read_text(encoding="utf-8"))
        rc3 = json.loads((ROOT / "docs/schemas/rc3-publication-authorization-v1.schema.json").read_text(encoding="utf-8"))
        rc1_value = {
            "schema_version": "gocode.release.rc1-qualification-decision/1",
            "candidate_binding_sha256": "a" * 64, "subject_sha256": "b" * 64,
            "matrix_sha256": "c" * 64, "bootstrap_sha256": "d" * 64,
            "candidate_sha256": "e" * 64, "policy_sha256": "f" * 64,
            "release_facts_sha256": "a" * 64,
            "approver": {key: "valid" for key in ["principal_id", "account_id", "lane_id", "key_id", "signature_profile_id"]},
            "valid_from": 1, "expires_at": 2, "revocation_epoch": 1,
            "disposition": "qualified_unsigned", "signing_allowed": False,
            "publication_allowed": False, "external_effects": [],
        }
        self.assertFalse(_errors(rc1, rc1_value))
        rc3_value = {
            "schema_version": "gocode.release.rc3-publication-authorization/1",
            "inventory_sha256": "a" * 64, "report_sha256": "b" * 64,
            "publication_manifest_sha256": "c" * 64, "executor_principal": "valid",
            "lane": "valid", "workflow_sha256": "d" * 64, "idempotency_namespace": "valid",
            "destination": "repo/releases", "channel": "stable", "valid_from": 1,
            "expires_at": 2, "revocation_epoch": 1, "no_effect": True, "external_effects": [],
        }
        for identifier in corpus["invalid_ids"]:
            invalid_rc1 = deepcopy(rc1_value)
            invalid_rc1["approver"]["principal_id"] = identifier
            invalid_rc3 = deepcopy(rc3_value)
            invalid_rc3["executor_principal"] = identifier
            self.assertTrue(_errors(rc1, invalid_rc1), identifier)
            self.assertTrue(_errors(rc3, invalid_rc3), identifier)
        for epoch in corpus["invalid_revocation_epochs"]:
            invalid_rc1 = deepcopy(rc1_value)
            invalid_rc1["revocation_epoch"] = epoch
            invalid_rc3 = deepcopy(rc3_value)
            invalid_rc3["revocation_epoch"] = epoch
            self.assertTrue(_errors(rc1, invalid_rc1), epoch)
            self.assertTrue(_errors(rc3, invalid_rc3), epoch)
    def test_closed_stage_schema_ids_and_draft_are_exact(self) -> None:
        schemas = ROOT / "docs/schemas"
        for name, schema_id in SCHEMAS.items():
            payload = json.loads((schemas / name).read_text(encoding="utf-8"))
            self.assertEqual(payload["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(payload["$id"], schema_id)
            self.assertFalse(payload.get("additionalProperties", True))

    def test_all_stage_schemas_have_non_empty_titles(self) -> None:
        schemas = ROOT / "docs/schemas"
        for name in SCHEMAS:
            with self.subTest(schema=name):
                payload = json.loads((schemas / name).read_text(encoding="utf-8"))
                self.assertIsInstance(payload.get("title"), str)
                self.assertTrue(payload["title"].strip())

    def test_publication_manifest_excludes_macos_preview(self) -> None:
        payload = json.loads((ROOT / "docs/schemas/publication-manifest-v1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["properties"]["artifacts"], {"const": ["linux", "windows"]})

    def test_unsigned_manifest_closes_all_v1_release_facts(self) -> None:
        schema = json.loads(
            (ROOT / "docs/schemas/unsigned-candidate-manifest-v1.schema.json").read_text(encoding="utf-8")
        )
        value = _unsigned_manifest()
        self.assertFalse(_errors(schema, value))
        for field in ["app_version", "release_sequence", "bundle_identity", "artifacts", "bundled_runtime", "macos_preview"]:
            invalid = deepcopy(value)
            invalid.pop(field)
            self.assertTrue(_errors(schema, invalid), field)
        for mutation in ("slot", "extra", "macos_public", "profiles"):
            invalid = deepcopy(value)
            if mutation == "slot":
                invalid["artifacts"][1]["artifact_slot_id"] = "linux-appimage"
            elif mutation == "extra":
                invalid["artifacts"].append(deepcopy(invalid["artifacts"][0]))
            elif mutation == "macos_public":
                invalid["macos_preview"]["publication_allowed"] = True
            else:
                invalid["artifacts"][0]["profile_bindings"] = []
            self.assertTrue(_errors(schema, invalid), mutation)

    def test_all_stage_contracts_have_exact_schema_version_and_closed_digests(self) -> None:
        for name, schema_id in SCHEMAS.items():
            payload = json.loads((ROOT / "docs/schemas" / name).read_text(encoding="utf-8"))
            self.assertIn("schema_version", payload["required"])
            self.assertEqual(payload["properties"]["schema_version"]["const"], schema_id)
        snapshot = json.loads((ROOT / "docs/schemas/promotion-state-snapshot-v1.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(snapshot["properties"]["revision"]["maximum"], 18446744073709551615)

    def test_publication_effect_schemas_close_the_durable_scope_and_evidence(self) -> None:
        schemas = ROOT / "docs/schemas"
        intent = json.loads((schemas / "publication-effect-intent-v1.schema.json").read_text(encoding="utf-8"))
        settlement = json.loads((schemas / "publication-effect-settlement-v1.schema.json").read_text(encoding="utf-8"))
        ledger = json.loads((schemas / "publication-effect-ledger-v1.schema.json").read_text(encoding="utf-8"))
        for schema in (intent, settlement, ledger):
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        for field in ["authority_instance_sha256", "rc3_authorization_sha256", "final_review_sha256", "allowlist_sha256", "allowlist_generation", "executor", "executable_sha256", "workflow_sha256", "generation"]:
            self.assertIn(field, intent["required"])
        self.assertEqual(settlement["properties"]["observed_result"]["enum"], ["succeeded", "absent", "inconclusive"])
        self.assertEqual(ledger["properties"]["claims"]["items"]["$ref"], "#/$defs/claim")

    def test_release_semantics_are_closed_and_fail_closed(self) -> None:
        schemas = ROOT / "docs/schemas"
        def schema(name: str) -> dict:
            return json.loads((schemas / name).read_text(encoding="utf-8"))
        rc1 = schema("release-rc1-qualification-decision-v1.schema.json")
        self.assertIn("release_facts_sha256", rc1["required"])
        self.assertEqual(rc1["properties"]["release_facts_sha256"], {"$ref": "#/$defs/digest"})
        self.assertEqual(rc1["properties"]["signing_allowed"], {"const": False})
        self.assertEqual(rc1["properties"]["publication_allowed"], {"const": False})
        self.assertEqual(rc1["properties"]["external_effects"]["maxItems"], 0)
        rc2 = schema("release-rc2-threshold-update-metadata-set-v2.schema.json")
        self.assertEqual(rc2["properties"]["root"]["$ref"], "#/$defs/root")
        self.assertEqual(rc2["properties"]["snapshot"]["$ref"], "#/$defs/snapshot")
        self.assertEqual(rc2["$defs"]["root_body"]["properties"]["role"], {"const": "root"})
        self.assertEqual(rc2["$defs"]["targets_body"]["properties"]["role"], {"const": "targets"})
        self.assertEqual(rc2["$defs"]["snapshot_body"]["properties"]["role"], {"const": "snapshot"})
        self.assertEqual(rc2["$defs"]["timestamp_body"]["properties"]["role"], {"const": "timestamp"})
        self.assertEqual(rc2["$defs"]["targets_body"]["properties"]["targets"]["items"], False)
        signing = schema("rc2-signing-authorization-v1.schema.json")
        self.assertEqual(
            signing["properties"]["pre_sign_artifacts"]["prefixItems"][0]["$ref"],
            "#/$defs/linux_appimage_plan",
        )
        self.assertEqual(
            signing["properties"]["pre_sign_artifacts"]["prefixItems"][1]["$ref"],
            "#/$defs/linux_deb_plan",
        )
        self.assertEqual(
            signing["properties"]["pre_sign_artifacts"]["prefixItems"][2]["$ref"],
            "#/$defs/windows_plan",
        )
        self.assertEqual(signing["properties"]["pre_sign_artifacts"]["items"], False)
        for role in ["signer", "runner", "reviewer", "update_issuer"]:
            self.assertEqual(signing["properties"][role]["$ref"], "#/$defs/identity")
        self.assertEqual(signing["$defs"]["artifact"]["properties"]["operation"], {"const": "native_sign"})
        record = schema("release-rc2-signed-artifact-record-v2.schema.json")
        for field in ["artifact_slot_id", "signing_authorization_sha256", "workflow_sha256", "effect_namespace", "effect_generation", "operation", "pre_sign_artifact_sha256", "pre_sign_artifact_length", "signer", "runner"]:
            self.assertIn(field, record["required"])
        self.assertEqual(record["properties"]["operation"], {"const": "native_sign"})
        self.assertEqual(record["properties"]["signer"]["$ref"], "#/$defs/identity")
        for field in [
            "native_signature_attestation_sha256", "certificate_chain_attestation_sha256",
            "timestamp_attestation_sha256", "secret_scan_attestation_sha256",
            "advisory_scan_attestation_sha256", "package_inspection_attestation_sha256",
            "install_attestation_sha256", "upgrade_attestation_sha256",
            "rollback_attestation_sha256", "uninstall_attestation_sha256",
        ]:
            self.assertIn(field, record["required"])
            self.assertEqual(record["properties"][field], {"$ref": "#/$defs/digest"})
        native = schema("rc2-native-evidence-v1.schema.json")
        self.assertEqual(native["properties"]["attestations"]["minItems"], 10)
        self.assertEqual(native["properties"]["attestations"]["items"], False)
        inventory = schema("signed-envelope-inventory-v1.schema.json")
        self.assertTrue(inventory["properties"]["artifact_records"]["uniqueItems"])
        report = schema("signed-envelope-verification-report-v1.schema.json")
        self.assertEqual(report["properties"]["linux_native_outcome"], {"const": "verified"})
        manifest = schema("publication-manifest-v1.schema.json")
        self.assertEqual(manifest["properties"]["artifacts"], {"const": ["linux", "windows"]})
        self.assertEqual(manifest["properties"]["macos_preview_excluded"], {"const": True})
        authorization = schema("rc3-publication-authorization-v1.schema.json")
        self.assertEqual(authorization["properties"]["no_effect"], {"const": True})
        self.assertEqual(authorization["properties"]["external_effects"]["maxItems"], 0)

    def test_threshold_v2_schema_closes_roles_slots_and_detached_proofs(self) -> None:
        schema = json.loads(
            (ROOT / "docs/schemas/release-rc2-threshold-update-metadata-set-v2.schema.json")
            .read_text(encoding="utf-8")
        )
        value = json.loads((ROOT / "crates/gocode-release-authority/tests/fixtures/threshold_v2_valid.json").read_text(encoding="utf-8"))
        self.assertFalse(_errors(schema, value))
        corpus = json.loads((ROOT / "crates/gocode-release-authority/tests/fixtures/threshold_v2_mutations.json").read_text(encoding="utf-8"))
        for entry in corpus:
            invalid = deepcopy(value)
            current = invalid
            for segment in entry["path"][:-1]:
                current = current[int(segment)] if segment.isdigit() else current[segment]
            current[entry["path"][-1]] = entry["value"]
            self.assertEqual(bool(_errors(schema, invalid)), entry["schema_reject"], entry["name"])
        for mutation in ("missing", "short", "order", "duplicate_key", "duplicate_proof"):
            invalid = deepcopy(value)
            if mutation == "missing": invalid["root"].pop("self_proof")
            elif mutation == "short": invalid["root"]["self_proof"][0]["signature"] = "a" * 126
            elif mutation == "order": invalid["targets"]["body"]["targets"].reverse()
            elif mutation == "duplicate_key": invalid["root"]["body"]["keyset"][1] = invalid["root"]["body"]["keyset"][0]
            else: invalid["root"]["self_proof"][1] = invalid["root"]["self_proof"][0]
            self.assertTrue(_errors(schema, invalid), mutation)


def _unsigned_manifest() -> dict:
    digest = "a" * 64
    rows = [
        ("linux-appimage", "linux-ubuntu-24_04-x86_64-production", "linux", "x86_64"),
        ("linux-deb", "linux-ubuntu-24_04-x86_64-production", "linux", "x86_64"),
        ("macos-app-development-adhoc", "macos-14-arm64-development-preview", "macos", "arm64"),
        ("macos-dmg-development-adhoc", "macos-14-arm64-development-preview", "macos", "arm64"),
        ("windows-installer-unsigned", "windows-11-24h2-x86_64-production", "windows", "x86_64"),
    ]
    return {
        "schema_version": "gocode.release.unsigned-candidate-manifest/1", "candidate_sha256": digest,
        "subject_sha256": digest, "matrix_sha256": digest, "bootstrap_sha256": digest,
        "policy_sha256": digest, "app_version": "1.0.0", "release_sequence": 1,
        "bundle_identity": "gocode-desktop", "bundled_runtime": {"version": "1.0.0", "sha256": digest},
        "artifacts": [{"artifact_slot_id": slot, "platform_scope_id": scope, "platform": platform,
                       "architecture": arch, "artifact_sha256": digest, "byte_length": index + 1,
                       "minimum_os_policy": {"policy_id": "v1-minimum-os", "policy_sha256": digest},
                       "profile_bindings": [{"profile_id": "gocode-bundled-runtime", "bundle_sha256": digest}]}
                      for index, (slot, scope, platform, arch) in enumerate(rows)],
        "macos_preview": {"platform_scope_id": "macos-14-arm64-development-preview",
                          "artifact_slot_ids": ["macos-app-development-adhoc", "macos-dmg-development-adhoc"],
                          "disposition": "development_preview", "publication_allowed": False},
    }


if __name__ == "__main__":
    unittest.main()
