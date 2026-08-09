import ast
import importlib
import inspect
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def model_module():
    try:
        return importlib.import_module("scripts.rc0_policy.model")
    except ModuleNotFoundError as error:
        raise AssertionError("RC0 fixture boundary is absent") from error


class Rc0PolicyBoundaryTests(unittest.TestCase):
    def test_checkout_defines_no_executable_runner_or_authority_issuer(self):
        policy_dir = ROOT / "scripts" / "rc0_policy"
        self.assertTrue(policy_dir.is_dir(), "fixture-only policy package is absent")
        self.assertFalse((policy_dir / "runner.py").exists())
        prohibited = {"IndependentRunner", "issue_report", "issue_declaration"}
        definitions = set()
        for path in policy_dir.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            definitions.update(
                node.name for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            )
        self.assertTrue(prohibited.isdisjoint(definitions))

    def test_candidate_cannot_choose_policy_key_bundle_or_selector(self):
        model = model_module()
        signature = inspect.signature(model.validate_fixture)
        self.assertEqual(tuple(signature.parameters), ("raw", "schema_id"))
        self.assertTrue({"key", "bundle_path", "selector", "runner"}.isdisjoint(signature.parameters))

    def test_fixture_harness_cannot_emit_report_declaration_or_gate_verdict(self):
        model = model_module()
        fixture = ROOT / "scripts/tests/fixtures/rc0_policy/fixture-policy.json"
        result = model.validate_fixture(
            fixture.read_bytes(), "gocode.rc0.schema.qualification-policy-bundle/3"
        )
        self.assertEqual(result.marker, "FIXTURE_LOCAL_INPUTS_SATISFIED")
        output = result.as_dict()
        self.assertEqual(
            set(output), {"canonical_sha256", "diagnostics", "marker", "record"}
        )
        serialized = json.dumps(output, sort_keys=True)
        for forbidden in ("RC0_QUALIFIED", '"gate_result"', '"declaration"'):
            self.assertNotIn(forbidden, serialized)

        invalid = model.validate_fixture(
            b'{"schema_id":"gocode.rc0.schema.candidate-record/3"}',
            "gocode.rc0.schema.candidate-record/3",
        )
        self.assertNotEqual(invalid.marker, "FIXTURE_LOCAL_INPUTS_SATISFIED")
        self.assertTrue(invalid.diagnostics)

    def test_release_and_publication_are_out_of_scope_not_gate_results(self):
        model = model_module()
        valid = [
            {"stage": stage, "report_stage_disposition": "OUT_OF_SCOPE"}
            for stage in ("RELEASE_APPROVAL", "PUBLICATION_AUTHORIZATION")
        ]
        self.assertEqual(model.validate_stage_dispositions(valid), ())
        invalid = [{**valid[0], "gate_result": "BLOCKED"}]
        self.assertTrue(model.validate_stage_dispositions(invalid))


if __name__ == "__main__":
    unittest.main()
