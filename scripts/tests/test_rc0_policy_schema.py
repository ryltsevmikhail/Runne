import importlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from scripts.tests.rc0_policy_fix_round2_cases import Rc0PolicyFixRound2Tests


SCHEMA_IDS = (
    "gocode.rc0.schema.candidate-record/3",
    "gocode.rc0.schema.source-gate-results/3",
    "gocode.rc0.schema.test-inventory/3",
    "gocode.rc0.schema.security-validation/3",
    "gocode.rc0.schema.documentation-validation/3",
    "gocode.rc0.schema.fail-closed-disposition/3",
    "gocode.rc0.schema.artifact-inventory/3",
    "gocode.rc0.schema.sbom-spdx-2.3/3",
    "gocode.rc0.schema.checksums-text/3",
    "gocode.rc0.schema.qualification-policy-bundle/3",
    "gocode.rc0.schema.verification-report/3",
)
ROOT = Path(__file__).resolve().parents[2]


def policy_module(name):
    try:
        return importlib.import_module(f"scripts.rc0_policy.{name}")
    except ModuleNotFoundError as error:
        raise AssertionError("RC0 fixture schema harness is absent") from error


class Rc0PolicySchemaTests(unittest.TestCase):
    def test_all_eleven_schemas_are_draft_2020_12_closed_objects(self):
        schemas = policy_module("schemas")
        self.assertEqual(set(schemas.SCHEMA_FILES), set(SCHEMA_IDS))
        for schema_id in SCHEMA_IDS:
            with self.subTest(schema_id=schema_id):
                schema = schemas.load_schema(schema_id)
                self.assertEqual(schema["$id"], schema_id)
                self.assertEqual(
                    schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
                )
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)

    def test_evidence_seal_requires_nine_direct_child_regular_blobs(self):
        model = policy_module("model")
        source = "a" * 40
        prefix = f"docs/evidence/rc0-candidates/{source}/"
        entries = {
            prefix + name: {"mode": "100644", "type": "blob", "data": name.encode()}
            for name in model.EVIDENCE_FILES
        }
        self.assertEqual(model.fixture_evidence_bundle_digest(entries).__len__(), 64)
        for mutation in ("missing", "nested", "mode", "type", "extra"):
            changed = {path: dict(entry) for path, entry in entries.items()}
            first = next(iter(changed))
            if mutation == "missing":
                changed.pop(first)
            elif mutation == "nested":
                changed[prefix + "nested/candidate-record.json"] = changed.pop(first)
            elif mutation == "mode":
                changed[first]["mode"] = "100755"
            elif mutation == "type":
                changed[first]["type"] = "symlink"
            else:
                changed[prefix + "extra.json"] = {
                    "mode": "100644", "type": "blob", "data": b"extra"
                }
            with self.subTest(mutation=mutation):
                with self.assertRaises(model.FixtureValidationError):
                    model.fixture_evidence_bundle_digest(changed)

    def test_artifact_checksum_and_spdx_sets_are_an_exact_bijection(self):
        model = policy_module("model")
        key = {"relative_path": "dist/gocode.tar", "sha256": "c" * 64}
        inventory = {"artifacts": [{**key, "locator": "cas:sha256:" + "c" * 64, "size": 3}]}
        checksums = {"artifacts": [{**key, "size": 3}]}
        spdx = {"artifact_bindings": [key]}
        self.assertEqual(model.validate_artifact_bijection(inventory, checksums, spdx), ())
        inventory["artifacts"][0]["locator"] = "cas:sha256:" + "d" * 64
        self.assertTrue(model.validate_artifact_bijection(inventory, checksums, spdx))
        inventory["artifacts"][0]["locator"] = "cas:sha256:" + "c" * 64
        checksums["artifacts"][0]["size"] = 4
        self.assertTrue(model.validate_artifact_bijection(inventory, checksums, spdx))
        checksums["artifacts"][0]["size"] = 3
        spdx["artifact_bindings"] = []
        self.assertTrue(model.validate_artifact_bijection(inventory, checksums, spdx))

    def test_fixture_artifact_parser_rejects_locator_digest_substitution(self):
        model = policy_module("model")
        canonical = policy_module("canonical")
        record = {
            "schema_id": "gocode.rc0.schema.artifact-inventory/3",
            "repository_id": "gocode",
            "candidate_source_revision": "a" * 40,
            "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
            "policy_digest": "b" * 64,
            "profile": "gocode.rc0.evidence-profile/3",
            "artifacts": [{
                "relative_path": "dist/gocode.tar", "sha256": "c" * 64,
                "size": 3, "locator": "cas:sha256:" + "d" * 64, "kind": "BINARY",
            }],
        }
        result = model.validate_fixture(
            canonical.canonical_bytes(record), "gocode.rc0.schema.artifact-inventory/3"
        )
        self.assertNotEqual(result.marker, "FIXTURE_LOCAL_INPUTS_SATISFIED")

    def test_checksums_text_requires_exact_headers_sorting_and_lf(self):
        model = policy_module("model")
        self.assertTrue(hasattr(model, "parse_checksums_text"), "strict checksums parser is absent")
        identity = (
            "repository_id=gocode\n"
            + "candidate_source_revision=" + "a" * 40 + "\n"
            + "evidence_attempt_id=018f0000-0000-7000-8000-000000000000\n"
            + "policy_digest=" + "b" * 64 + "\n"
        )
        line = "c" * 64 + " 3 dist/gocode.tar\n"
        parsed = model.parse_checksums_text((identity + line).encode())
        self.assertEqual(parsed["artifacts"][0]["size"], 3)
        for raw in (
            (identity + line.rstrip("\n")).encode(),
            (identity.replace("\n", "\r\n") + line).encode(),
            (identity + line + line).encode(),
        ):
            with self.subTest(raw=raw[-80:]):
                with self.assertRaises(model.FixtureValidationError):
                    model.parse_checksums_text(raw)

    def test_model_enforces_identity_source_and_gate_mapping_bindings(self):
        model = policy_module("model")
        self.assertTrue(hasattr(model, "validate_record_bindings"))
        identity = {
            "repository_id": "gocode",
            "candidate_source_revision": "a" * 40,
            "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
            "policy_digest": "b" * 64,
            "profile": "gocode.rc0.evidence-profile/3",
        }
        records = {
            "candidate-record.json": dict(identity),
            "source-gate-results.json": {
                **identity,
                "capture": {
                    "head_revision": "c" * 40,
                    "captured_origin_main_revision": "a" * 40,
                },
            },
            "test-inventory.json": {
                **identity,
                "tests": [{"source_sha": "a" * 40}],
            },
            "artifact-inventory.json": {**identity, "artifacts": []},
            "checksums.txt": {key: value for key, value in identity.items() if key != "profile"} | {"artifacts": []},
            "sbom.spdx.json": {**identity, "artifact_bindings": []},
            "verification-report.json": {
                "repository_id": "gocode",
                "candidate_source_sha": "a" * 40,
                "evidence_attempt_id": identity["evidence_attempt_id"],
                "policy_digest": "b" * 64,
                "profile": identity["profile"],
                "exact_artifact_bindings": [],
                "required_gate_results": [{
                    "execution_outcome": "FAIL", "gate_result": "PASS",
                    "stage": "SOURCE_CANDIDATE",
                }],
                "stage_dispositions": [],
            },
        }
        diagnostics = model.validate_record_bindings(records)
        self.assertTrue(any("head_revision" in item for item in diagnostics))
        self.assertTrue(any("gate mapping" in item for item in diagnostics))

    def test_policy_inventory_rejects_duplicate_or_noncanonical_keys(self):
        model = policy_module("model")
        self.assertTrue(hasattr(model, "validate_policy_inventory"))
        policy = json.loads(
            (ROOT / "scripts/tests/fixtures/rc0_policy/fixture-policy.json").read_text()
        )
        self.assertEqual(model.validate_policy_inventory(policy), ())
        mutations = []
        duplicate_schema = deepcopy(policy)
        duplicate_schema["expected_schema_digests"][-1]["schema_id"] = duplicate_schema["expected_schema_digests"][0]["schema_id"]
        duplicate_schema["expected_schema_digests"][-1]["sha256"] = "0" * 64
        mutations.append(duplicate_schema)
        arbitrary_schema = deepcopy(policy)
        arbitrary_schema["expected_schema_digests"][-1]["schema_id"] = "candidate.chosen/3"
        mutations.append(arbitrary_schema)
        self.assertTrue(
            policy_module("schemas").validate_schema(
                arbitrary_schema, "gocode.rc0.schema.qualification-policy-bundle/3"
            )
        )
        duplicate_gate = deepcopy(policy)
        duplicate_gate["required_gates"].append({**duplicate_gate["required_gates"][0], "stage": "PRODUCTION_QUALIFICATION"})
        mutations.append(duplicate_gate)
        duplicate_selector = deepcopy(policy)
        duplicate_selector["required_gates"][0]["selectors"] *= 2
        mutations.append(duplicate_selector)
        source_only = deepcopy(policy)
        source_only["required_gates"] = [gate for gate in source_only["required_gates"] if gate["stage"] == "SOURCE_CANDIDATE"]
        mutations.append(source_only)
        malformed_key = deepcopy(policy)
        malformed_key["expected_schema_digests"][-1]["schema_id"] = ["not", "a", "key"]
        mutations.append(malformed_key)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                try:
                    diagnostics = model.validate_policy_inventory(mutation)
                except Exception as error:
                    self.fail(f"policy diagnostics leaked {type(error).__name__}")
                self.assertTrue(diagnostics)

    def test_portable_paths_and_immutable_locators_reject_aliases(self):
        model = policy_module("model")
        self.assertTrue(hasattr(model, "validate_portable_relative_path"))
        self.assertEqual(model.validate_portable_relative_path("dist/продукт.tar"), ())
        for path in ("/abs", "C:/drive", "a\\b", "a//b", ".", "..", "a/./b", "a/../b", "a\x00b"):
            with self.subTest(path=path):
                self.assertTrue(model.validate_portable_relative_path(path))
        valid = "cas:sha256:" + "c" * 64
        self.assertEqual(model.validate_content_locator(valid), ())
        for locator in ("latest", "git:HEAD:dist/a", "git:main:dist/a", "cas:sha256:" + "C" * 64):
            with self.subTest(locator=locator):
                self.assertTrue(model.validate_content_locator(locator))

    def test_source_capture_requires_raw_current_identity_equality(self):
        model = policy_module("model")
        self.assertTrue(hasattr(model, "validate_source_capture"))
        source = "a" * 40
        pinned = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
        capture = {
            "captured_origin_main_revision": source,
            "head_revision": source,
            "raw_tree_oid": "b" * 40,
            "current_tree_oid": "b" * 40,
            "raw_gitmodules_sha256": "c" * 64,
            "current_gitmodules_sha256": "c" * 64,
            "raw_opencode_gitlink_revision": pinned,
            "current_opencode_gitlink_revision": pinned,
            "capture_evidence_kind": "RAW_GIT_OBJECTS",
        }
        self.assertEqual(model.validate_source_capture(capture, source), ())
        missing_raw_tree = dict(capture)
        missing_raw_tree.pop("raw_tree_oid")
        missing_raw_tree.pop("current_tree_oid")
        self.assertTrue(
            any("raw_tree_oid" in item for item in model.validate_source_capture(missing_raw_tree, source))
        )
        for left, right in (
            ("raw_tree_oid", "current_tree_oid"),
            ("raw_gitmodules_sha256", "current_gitmodules_sha256"),
            ("raw_opencode_gitlink_revision", "current_opencode_gitlink_revision"),
        ):
            changed = dict(capture)
            changed[right] = "d" * len(changed[right])
            with self.subTest(field=right):
                diagnostics = model.validate_source_capture(changed, source)
                self.assertTrue(any(left in item or right in item for item in diagnostics))

    def test_schemas_require_raw_capture_and_reject_path_or_policy_aliases(self):
        schemas = policy_module("schemas")
        source = "a" * 40
        identity = {
            "schema_id": "gocode.rc0.schema.source-gate-results/3",
            "repository_id": "gocode",
            "candidate_source_revision": source,
            "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
            "policy_digest": "b" * 64,
            "profile": "gocode.rc0.evidence-profile/3",
        }
        capture = {
            "remote_url": "https://github.com/Ryltsevmg/gocode",
            "captured_origin_main_revision": source,
            "head_revision": source,
            "tree_clean": True,
        }
        diagnostics = schemas.validate_schema(
            {**identity, "capture": capture}, "gocode.rc0.schema.source-gate-results/3"
        )
        self.assertTrue(any("raw_tree_oid" in item for item in diagnostics))
        artifact = {
            "relative_path": "../escape", "sha256": "c" * 64,
            "size": 1, "locator": "latest", "kind": "BINARY",
        }
        artifact_record = {
            **{key: value for key, value in identity.items() if key != "schema_id"},
            "schema_id": "gocode.rc0.schema.artifact-inventory/3",
            "artifacts": [artifact],
        }
        diagnostics = schemas.validate_schema(
            artifact_record, "gocode.rc0.schema.artifact-inventory/3"
        )
        self.assertTrue(any("relative_path" in item or "locator" in item for item in diagnostics))


if __name__ == "__main__":
    unittest.main()
