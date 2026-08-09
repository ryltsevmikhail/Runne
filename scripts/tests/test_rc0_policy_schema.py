import importlib
import unittest


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
        checksums["artifacts"][0]["size"] = 4
        self.assertTrue(model.validate_artifact_bijection(inventory, checksums, spdx))
        checksums["artifacts"][0]["size"] = 3
        spdx["artifact_bindings"] = []
        self.assertTrue(model.validate_artifact_bijection(inventory, checksums, spdx))

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


if __name__ == "__main__":
    unittest.main()
