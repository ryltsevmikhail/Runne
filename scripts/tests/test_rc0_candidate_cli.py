import ast
import importlib
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts/tests/fixtures/rc0_candidate"


def candidate_cli():
    try:
        return importlib.import_module("scripts.rc0_candidate.cli")
    except ModuleNotFoundError as error:
        raise AssertionError("candidate CLI is absent") from error


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "scripts.rc0_candidate.cli", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


class Rc0CandidateCliTests(unittest.TestCase):
    def test_candidate_cannot_emit_report_declaration_or_gate_verdict(self):
        candidate_cli()
        package = ROOT / "scripts/rc0_candidate"
        prohibited = {"IndependentRunner", "issue_report", "issue_declaration", "emit_gate_verdict"}
        definitions = set()
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            definitions.update(
                node.name for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            )
        self.assertTrue(prohibited.isdisjoint(definitions))
        for token in ("--trusted-key", "--policy-path", "--runner-selector", "--release", "--publication", "report", "declaration", "verdict"):
            with self.subTest(token=token):
                result = run_cli(token)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((result.stdout, result.stderr), ("", ""))

    def test_fixture_local_inputs_satisfied_requires_all_local_inputs(self):
        cli = candidate_cli()
        complete = cli.summarize_fixture_local_inputs(
            {
                "fixture_only": True,
                "source_capture": "FIXTURE_LOCAL_INPUTS_SATISFIED",
                "evidence_construction": "FIXTURE_LOCAL_INPUTS_SATISFIED",
                "local_command_evidence": [{"id": "fixture.test", "satisfied": True}],
            }
        )
        self.assertEqual(complete.as_dict(), {"status": "FIXTURE_LOCAL_INPUTS_SATISFIED"})
        for missing in ("source_capture", "evidence_construction", "local_command_evidence"):
            data = {
                "fixture_only": True,
                "source_capture": "FIXTURE_LOCAL_INPUTS_SATISFIED",
                "evidence_construction": "FIXTURE_LOCAL_INPUTS_SATISFIED",
                "local_command_evidence": [{"id": "fixture.test", "satisfied": True}],
            }
            data.pop(missing)
            with self.subTest(missing=missing):
                summary = cli.summarize_fixture_local_inputs(data)
                self.assertEqual(summary.status, "BLOCKED")

        satisfied = run_cli("fixture-dry-run", "--local-inputs", str(FIXTURES / "local-inputs-satisfied.json"))
        self.assertEqual((satisfied.returncode, satisfied.stdout, satisfied.stderr), (0, "FIXTURE_LOCAL_INPUTS_SATISFIED\n", ""))
        blocked = run_cli("fixture-dry-run", "--local-inputs", str(FIXTURES / "local-inputs-blocked.json"))
        self.assertEqual((blocked.returncode, blocked.stdout, blocked.stderr), (2, "BLOCKED(LOCAL_INPUTS_UNAVAILABLE)\n", ""))

    def test_missing_external_authority_is_blocked(self):
        result = run_cli()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (2, "BLOCKED(ADR_OR_POLICY_UNAVAILABLE)\n", ""))


if __name__ == "__main__":
    unittest.main()
