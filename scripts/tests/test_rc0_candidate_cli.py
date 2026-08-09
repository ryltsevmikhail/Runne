import ast
import importlib
import json
import shutil
import subprocess
import sys
import tempfile
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
    def test_ci_local_is_nonrecursive_and_consumes_one_receipt(self):
        wrapper = (ROOT / "scripts/ci-local.sh").read_text(encoding="utf-8")
        self.assertEqual(wrapper.count('bash "$input_script" "$receipt"'), 1)
        self.assertNotIn("ci-local.sh", "\n".join(wrapper.splitlines()[2:]))
        self.assertNotIn("scripts.rc0_candidate.cli", wrapper)

        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        with tempfile.TemporaryDirectory() as location:
            fixture_root = Path(location) / "repository"
            self._receipt_fixture(fixture_root)
            receipt_directory = Path(location) / "receipt"
            receipt_directory.mkdir(mode=0o700)
            receipt = receipt_directory / "local-inputs-receipt.json"
            receipt_module.issue_local_input_receipt(
                fixture_root,
                receipt,
                fixture_root / "scripts/ci-local-inputs.sh",
                "rustc 1.97.1 (8bab26f4f 2026-07-14)",
                "rustc 1.95.0 (000000000 2026-01-01)",
            )
            record = receipt_module.validate_local_input_receipt(
                fixture_root, receipt, fixture_root / "scripts/ci-local-inputs.sh",
                fixture_root / "scripts/rc0_candidate/inventories/source-candidate-v1.json",
                consume=True,
            )
            self.assertEqual(record["local_inputs"], "LOCAL_INPUTS_COMPLETE")
            self.assertFalse(receipt.exists())
            with self.assertRaises(receipt_module.LocalInputReceiptError):
                receipt_module.validate_local_input_receipt(
                    fixture_root, receipt, fixture_root / "scripts/ci-local-inputs.sh",
                    fixture_root / "scripts/rc0_candidate/inventories/source-candidate-v1.json",
                    consume=True,
                )

    def test_ci_local_never_invokes_pnpm_ci_local(self):
        wrapper = (ROOT / "scripts/ci-local.sh").read_text(encoding="utf-8")
        self.assertNotIn("pnpm ci:local", wrapper)

    def test_local_success_never_maps_to_rc0_qualified(self):
        summary = candidate_cli().structural_summary("FIXTURE_LOCAL_INPUTS_SATISFIED")
        self.assertEqual(
            summary,
            {
                "fixture_local_inputs": "FIXTURE_LOCAL_INPUTS_SATISFIED",
                "production_qualification": "BLOCKED",
                "release_approval": "OUT_OF_SCOPE",
                "publication_authorization": "OUT_OF_SCOPE",
            },
        )
        self.assertNotIn("RC0_QUALIFIED", summary.values())

    def test_missing_external_policy_is_blocked_not_pass(self):
        summary = candidate_cli().structural_summary("FIXTURE_LOCAL_INPUTS_SATISFIED")
        self.assertEqual(summary["production_qualification"], "BLOCKED")
        self.assertNotIn("PASS", summary.values())

    def test_receipt_rejects_noncanonical_or_stale_inventory(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        with tempfile.TemporaryDirectory() as location:
            fixture_root = Path(location) / "repository"
            self._receipt_fixture(fixture_root)
            receipt_directory = Path(location) / "receipt"
            receipt_directory.mkdir(mode=0o700)
            receipt = receipt_directory / "receipt.json"
            input_script = fixture_root / "scripts/ci-local-inputs.sh"
            inventory = fixture_root / "scripts/rc0_candidate/inventories/source-candidate-v1.json"
            receipt_module.issue_local_input_receipt(
                fixture_root, receipt, input_script,
                "rustc 1.97.1 (8bab26f4f 2026-07-14)",
                "rustc 1.95.0 (000000000 2026-01-01)",
            )
            inventory.write_bytes(inventory.read_bytes() + b"\n")
            with self.assertRaisesRegex(receipt_module.LocalInputReceiptError, "source|inventory"):
                receipt_module.validate_local_input_receipt(
                    fixture_root, receipt, input_script, inventory, consume=True,
                )
            self.assertTrue(receipt.exists())

    def test_receipt_rejects_expired_canonical_record(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        canonical = importlib.import_module("scripts.rc0_policy.canonical")
        with tempfile.TemporaryDirectory() as location:
            fixture_root = Path(location) / "repository"
            self._receipt_fixture(fixture_root)
            receipt_directory = Path(location) / "receipt"
            receipt_directory.mkdir(mode=0o700)
            receipt = receipt_directory / "receipt.json"
            input_script = fixture_root / "scripts/ci-local-inputs.sh"
            inventory = fixture_root / "scripts/rc0_candidate/inventories/source-candidate-v1.json"
            record = receipt_module.issue_local_input_receipt(
                fixture_root, receipt, input_script,
                "rustc 1.97.1 (8bab26f4f 2026-07-14)",
                "rustc 1.95.0 (000000000 2026-01-01)",
            )
            self.assertIn("issued_at_unix", record)
            record["issued_at_unix"] = 1
            receipt.write_bytes(canonical.canonical_bytes(record))
            with self.assertRaisesRegex(receipt_module.LocalInputReceiptError, "stale"):
                receipt_module.validate_local_input_receipt(
                    fixture_root, receipt, input_script, inventory, consume=True,
                )

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

    def test_fixture_input_open_detects_path_replacement(self):
        cli = candidate_cli()
        with tempfile.TemporaryDirectory() as location:
            root = Path(location)
            path = root / "inputs.json"
            path.write_bytes((FIXTURES / "local-inputs-satisfied.json").read_bytes())

            def replace(stage, opened_path):
                if stage == "after-open":
                    replacement = root / "replacement.json"
                    replacement.write_bytes((FIXTURES / "local-inputs-blocked.json").read_bytes())
                    replacement.replace(opened_path)

            self.assertIsNone(cli._load_inputs(str(path), mutation_hook=replace))

    def _receipt_fixture(self, root):
        (root / "scripts/rc0_candidate/inventories").mkdir(parents=True)
        (root / "docs/rc0").mkdir(parents=True)
        for relative in (
            "scripts/rc0_candidate/inventories/source-candidate-v1.json",
            "scripts/rc0_candidate/inventories/local-reliability-v1.json",
            "scripts/rc0_candidate/inventories/phase3-v1.json",
            "docs/rc0/taxonomy-migration-v1.json",
        ):
            source = ROOT / relative
            if source.exists():
                shutil.copy2(source, root / relative)
        (root / "scripts/ci-local-inputs.sh").write_text("#!/bin/sh\nexit 0\n")
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "--quiet", "-m", "fixture"], check=True)


if __name__ == "__main__":
    unittest.main()
