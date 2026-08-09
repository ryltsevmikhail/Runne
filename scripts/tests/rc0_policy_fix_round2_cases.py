"""Focused regression cases imported by test_rc0_policy_schema."""

import json
import unittest
from copy import deepcopy
from pathlib import Path

from scripts.rc0_policy import model, schemas
from scripts.tests.test_rc0_policy_boundary import report_fixture

ROOT = Path(__file__).resolve().parents[2]


def fixture_policy():
    return json.loads(
        (ROOT / "scripts/tests/fixtures/rc0_policy/fixture-policy.json").read_text()
    )


def artifact_record(locator):
    return {
        "schema_id": "gocode.rc0.schema.artifact-inventory/3",
        "repository_id": "gocode",
        "candidate_source_revision": "a" * 40,
        "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
        "policy_digest": "b" * 64,
        "profile": "gocode.rc0.evidence-profile/3",
        "artifacts": [{
            "relative_path": "dist/gocode.tar",
            "sha256": "f" * 64,
            "size": 3,
            "locator": locator,
            "kind": "BINARY",
        }],
    }


class Rc0PolicyFixRound2Tests(unittest.TestCase):
    def test_direct_policy_and_matching_report_reject_invalid_gate_ids(self):
        invalid_ids = ("", "Uppercase", ".leading", "path/gate", "a" * 129)
        for gate_id in invalid_ids:
            policy = fixture_policy()
            policy["required_gates"][0]["gate_id"] = gate_id
            with self.subTest(gate_id=gate_id):
                self.assertTrue(model.validate_policy_inventory(policy))
                self.assertTrue(any(
                    "gate_id" in item for item in schemas.validate_schema(
                        policy, "gocode.rc0.schema.qualification-policy-bundle/3"
                    )
                ))
            _, binding, report = report_fixture()
            report["required_gate_results"][0]["gate_id"] = gate_id
            self.assertTrue(model.validate_report_against_policy(report, policy, binding))

    def test_locator_schemas_reject_git_path_alias_matrix_without_model(self):
        revision = "a" * 40
        invalid = (
            f"git:{revision}:",
            f"git:{revision}:./escape",
            f"git:{revision}:../escape",
            f"git:{revision}:a/../escape",
            f"git:{revision}:a/./file",
            f"git:{revision}:/absolute",
            f"git:{revision}:a\\file",
            f"git:{revision}:a//file",
            f"git:{revision}:a/",
            f"git:{revision}:a/\x00/file",
            "git:HEAD:dist/file",
            "git:" + "A" * 40 + ":dist/file",
        )
        for locator in invalid:
            with self.subTest(locator=locator):
                artifact_diagnostics = schemas.validate_schema(
                    artifact_record(locator),
                    "gocode.rc0.schema.artifact-inventory/3",
                )
                self.assertTrue(any("locator" in item for item in artifact_diagnostics))
                _, _, report = report_fixture()
                report.update(
                    schema_id="gocode.rc0.schema.verification-report/3",
                    runner_identity={
                        "runner_class": "fixture", "executable_digest": "e" * 64,
                    },
                    issued_at="2026-08-09T00:00:00.000000Z",
                )
                report["exact_artifact_bindings"][0]["locator"] = locator
                report_diagnostics = schemas.validate_schema(
                    report, "gocode.rc0.schema.verification-report/3"
                )
                self.assertTrue(any("locator" in item for item in report_diagnostics))
