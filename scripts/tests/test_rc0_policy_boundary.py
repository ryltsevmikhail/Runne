import ast
import importlib
import inspect
import json
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def model_module():
    try:
        return importlib.import_module("scripts.rc0_policy.model")
    except ModuleNotFoundError as error:
        raise AssertionError("RC0 fixture boundary is absent") from error


def report_fixture():
    policy = json.loads(
        (ROOT / "scripts/tests/fixtures/rc0_policy/fixture-policy.json").read_text()
    )
    artifact = {
        "relative_path": "dist/gocode.tar",
        "sha256": "f" * 64,
        "size": 3,
        "locator": "cas:sha256:" + "f" * 64,
    }
    binding = {
        "repository_id": "gocode",
        "candidate_source_sha": "a" * 40,
        "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
        "observed_evidence_revision": "b" * 40,
        "evidence_bundle_digest": "d" * 64,
        "policy_revision": 3,
        "policy_digest": "c" * 64,
        "profile": "gocode.rc0.evidence-profile/3",
        "exact_artifact_bindings": [artifact],
    }
    results = [
        {
            "gate_id": gate["gate_id"],
            "stage": gate["stage"],
            "execution_outcome": "PASS",
            "gate_result": "PASS",
            "binding": deepcopy(binding),
        }
        for gate in policy["required_gates"]
    ]
    report = {
        **binding,
        "required_gate_results": results,
        "source_candidate_gate": {"gate_result": "PASS"},
        "production_qualification_gate": {"gate_result": "PASS"},
        "evidence_seal_gate": {"gate_result": "PASS"},
        "overall_candidate_gate": {"gate_result": "PASS"},
        "stage_dispositions": [
            {"stage": stage, "report_stage_disposition": "OUT_OF_SCOPE"}
            for stage in ("RELEASE_APPROVAL", "PUBLICATION_AUTHORIZATION")
        ],
    }
    return policy, binding, report


def evidence_fixture(artifact):
    identity = {
        "repository_id": "gocode",
        "candidate_source_revision": "a" * 40,
        "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
        "policy_digest": "c" * 64,
        "profile": "gocode.rc0.evidence-profile/3",
    }
    pinned = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
    records = {name: dict(identity) for name in model_module().EVIDENCE_FILES}
    records["source-gate-results.json"]["capture"] = {
        "head_revision": "a" * 40, "captured_origin_main_revision": "a" * 40,
        "raw_tree_oid": "b" * 40, "current_tree_oid": "b" * 40,
        "raw_gitmodules_sha256": "d" * 64, "current_gitmodules_sha256": "d" * 64,
        "raw_opencode_gitlink_revision": pinned,
        "current_opencode_gitlink_revision": pinned,
        "capture_evidence_kind": "RAW_GIT_OBJECTS",
    }
    records["test-inventory.json"]["tests"] = []
    records["artifact-inventory.json"]["artifacts"] = [artifact]
    records["checksums.txt"].pop("profile")
    records["checksums.txt"]["artifacts"] = [{key: artifact[key] for key in ("relative_path", "sha256", "size")}]
    records["sbom.spdx.json"]["artifact_bindings"] = [{key: artifact[key] for key in ("relative_path", "sha256")}]
    return records


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

    def test_report_requires_exact_nonvacuous_policy_gate_set(self):
        model = model_module()
        self.assertTrue(hasattr(model, "validate_report_against_policy"))
        policy, binding, report = report_fixture()
        self.assertEqual(model.validate_report_against_policy(report, policy, binding), ())
        duplicate = deepcopy(report)
        duplicate["required_gate_results"].append({
            **deepcopy(duplicate["required_gate_results"][0]),
            "execution_outcome": "FAIL",
            "gate_result": "BLOCKED",
            "blocked_reason": "REQUIRED_GATE_FAILED",
        })
        omitted = deepcopy(report)
        omitted["required_gate_results"].pop()
        extra = deepcopy(report)
        extra["required_gate_results"].append({
            **deepcopy(extra["required_gate_results"][0]), "gate_id": "candidate-extra"
        })
        for changed in (duplicate, omitted, extra):
            with self.subTest(count=len(changed["required_gate_results"])):
                diagnostics = model.validate_report_against_policy(changed, policy, binding)
                self.assertTrue(any("REQUIRED_GATE_MISMATCH" in item for item in diagnostics))

    def test_report_schema_requires_complete_nested_gate_binding(self):
        schemas = importlib.import_module("scripts.rc0_policy.schemas")
        _, _, report = report_fixture()
        report.update(
            schema_id="gocode.rc0.schema.verification-report/3",
            runner_identity={"runner_class": "fixture", "executable_digest": "e" * 64},
            issued_at="2026-08-09T00:00:00.000000Z",
        )
        self.assertEqual(
            schemas.validate_schema(report, "gocode.rc0.schema.verification-report/3"), ()
        )
        report["required_gate_results"][0]["binding"].pop("evidence_bundle_digest")
        diagnostics = schemas.validate_schema(
            report, "gocode.rc0.schema.verification-report/3"
        )
        self.assertTrue(any("evidence_bundle_digest" in item for item in diagnostics))

    def test_report_artifacts_must_bind_the_evidence_inventory(self):
        model = model_module()
        policy, binding, report = report_fixture()
        evidence_artifact = deepcopy(binding["exact_artifact_bindings"][0])
        evidence_artifact["sha256"] = "e" * 64
        evidence_artifact["locator"] = "cas:sha256:" + "e" * 64
        records = evidence_fixture(evidence_artifact)
        records["verification-report.json"] = report
        diagnostics = model.validate_record_bindings(records, policy, binding)
        self.assertTrue(any("artifact" in item for item in diagnostics))

    def test_report_rejects_incomplete_binding_and_aggregate_mismatch(self):
        model = model_module()
        self.assertTrue(hasattr(model, "validate_report_against_policy"))
        policy, binding, report = report_fixture()
        mutations = []
        for field, replacement in (
            ("observed_evidence_revision", "e" * 40),
            ("evidence_bundle_digest", "e" * 64),
            ("policy_revision", 4),
        ):
            changed = deepcopy(report)
            changed[field] = replacement
            mutations.append(changed)
        changed = deepcopy(report)
        changed["required_gate_results"][0]["binding"]["observed_evidence_revision"] = "e" * 40
        mutations.append(changed)
        changed = deepcopy(report)
        changed["source_candidate_gate"] = {
            "gate_result": "BLOCKED", "blocked_reason": "REQUIRED_GATE_MISMATCH"
        }
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(index=mutations.index(changed)):
                self.assertTrue(model.validate_report_against_policy(changed, policy, binding))
        locator_alias = deepcopy(report)
        locator_binding = deepcopy(binding)
        for bound in [locator_alias, *[item["binding"] for item in locator_alias["required_gate_results"]], locator_binding]:
            bound["exact_artifact_bindings"][0]["locator"] = "cas:sha256:" + "e" * 64
        self.assertTrue(
            model.validate_report_against_policy(locator_alias, policy, locator_binding)
        )

    def test_report_enforces_exact_required_gate_blocked_reasons(self):
        model = model_module()
        self.assertTrue(hasattr(model, "validate_report_against_policy"))
        policy, binding, report = report_fixture()
        failed = deepcopy(report)
        failed_result = failed["required_gate_results"][0]
        failed_result.update(
            execution_outcome="FAIL",
            gate_result="BLOCKED",
            blocked_reason="REQUIRED_GATE_FAILED",
        )
        failed["source_candidate_gate"] = {
            "gate_result": "BLOCKED", "blocked_reason": "REQUIRED_GATE_FAILED"
        }
        failed["overall_candidate_gate"] = {
            "gate_result": "BLOCKED", "blocked_reason": "REQUIRED_GATE_FAILED"
        }
        self.assertEqual(model.validate_report_against_policy(failed, policy, binding), ())
        for reason in (
            "REQUIRED_GATE_NOT_RUN",
            "REQUIRED_GATE_MISMATCH",
            "EVIDENCE_UNAVAILABLE",
            None,
        ):
            changed = deepcopy(failed)
            if reason is None:
                changed["required_gate_results"][0].pop("blocked_reason")
            else:
                changed["required_gate_results"][0]["blocked_reason"] = reason
            with self.subTest(reason=reason):
                self.assertTrue(model.validate_report_against_policy(changed, policy, binding))
        for reason in (
            "REQUIRED_GATE_EVIDENCE_UNAVAILABLE",
            "REQUIRED_GATE_POLICY_UNAVAILABLE",
            "REQUIRED_GATE_AUTHORITY_UNAVAILABLE",
        ):
            unavailable = deepcopy(report)
            unavailable["evidence_seal_gate"] = {
                "gate_result": "BLOCKED", "blocked_reason": reason,
            }
            unavailable["overall_candidate_gate"] = {
                "gate_result": "BLOCKED", "blocked_reason": reason,
            }
            with self.subTest(unavailable_reason=reason):
                self.assertEqual(
                    model.validate_report_against_policy(unavailable, policy, binding), ()
                )


if __name__ == "__main__":
    unittest.main()
