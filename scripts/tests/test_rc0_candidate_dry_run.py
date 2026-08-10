import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts/tests/fixtures/rc0_candidate/final-dry-run"
COMPLETE = FIXTURES / "complete-local-inputs.json"


def candidate_cli():
    from scripts.rc0_candidate import cli

    return cli


def invoke(arguments, receipt_result=None):
    cli = candidate_cli()
    output = io.StringIO()
    with patch.object(
        cli,
        "validate_local_input_receipt",
        side_effect=receipt_result,
    ) as receipt_validator, redirect_stdout(output):
        status = cli.main(arguments)
    return status, output.getvalue(), receipt_validator


def invoke_real(arguments, root):
    cli = candidate_cli()
    output = io.StringIO()
    with patch.object(cli, "_ROOT", root), redirect_stdout(output):
        status = cli.main(arguments)
    return status, output.getvalue()


def final_arguments(receipt="receipt.json"):
    return [
        "fixture-final-dry-run",
        "--local-inputs",
        str(COMPLETE),
        "--receipt",
        receipt,
        "--inventory",
        "scripts/rc0_candidate/inventories/source-candidate-v1.json",
    ]


class Rc0CandidateDryRunTests(unittest.TestCase):
    def test_all_local_code_docs_and_inventory_inputs_are_required_before_fixture_local_inputs_satisfied(self):
        cli = candidate_cli()
        complete = json.loads(COMPLETE.read_text(encoding="utf-8"))
        expected_ids = {
            "architecture.boundary",
            "diff.clean",
            "docs.strict",
            "phase3.exact-tuples",
            "python.focused",
            "rust.focused",
            "source-length.max-300",
            "typescript.focused",
        }
        self.assertEqual(
            {entry["id"] for entry in complete["local_command_evidence"]},
            expected_ids,
        )

        status, output, validator = invoke(final_arguments())
        self.assertEqual(status, 0)
        self.assertTrue(output.startswith("FIXTURE_LOCAL_INPUTS_SATISFIED\n"))
        validator.assert_called_once_with(
            ROOT,
            Path("receipt.json"),
            Path("scripts/rc0_candidate/inventories/source-candidate-v1.json"),
            consume=True,
        )

        for missing_id in sorted(expected_ids):
            with self.subTest(missing_id=missing_id), tempfile.TemporaryDirectory() as location:
                incomplete = dict(complete)
                incomplete["local_command_evidence"] = [
                    entry
                    for entry in complete["local_command_evidence"]
                    if entry["id"] != missing_id
                ]
                path = Path(location) / "incomplete.json"
                path.write_text(json.dumps(incomplete, sort_keys=True), encoding="utf-8")
                arguments = final_arguments()
                arguments[2] = str(path)
                status, output, validator = invoke(arguments)
                self.assertEqual((status, output), (2, "BLOCKED(LOCAL_INPUTS_UNAVAILABLE)\n"))
                validator.assert_not_called()

        receipt_error = cli.LocalInputReceiptError("missing receipt")
        status, output, validator = invoke(final_arguments(), receipt_result=receipt_error)
        self.assertEqual((status, output), (2, "BLOCKED(LOCAL_INPUTS_UNAVAILABLE)\n"))
        validator.assert_called_once()

        for field in (
            "artifact_construction",
            "fixture_only",
            "fixture_policy",
            "fixture_trust",
            "source_capture",
        ):
            with self.subTest(invalid_field=field):
                invalid = dict(complete)
                invalid[field] = False
                self.assertEqual(cli.summarize_final_dry_run_inputs(invalid).status, "BLOCKED")
        for mutation in ("duplicate", "unknown", "false"):
            with self.subTest(lane_mutation=mutation):
                invalid = json.loads(json.dumps(complete))
                if mutation == "duplicate":
                    invalid["local_command_evidence"][-1] = dict(
                        invalid["local_command_evidence"][0]
                    )
                elif mutation == "unknown":
                    invalid["local_command_evidence"][0]["id"] = "fixture.unknown"
                else:
                    invalid["local_command_evidence"][0]["satisfied"] = False
                self.assertEqual(cli.summarize_final_dry_run_inputs(invalid).status, "BLOCKED")

        with tempfile.TemporaryDirectory() as location:
            fixture_root = Path(location) / "repository"
            self._receipt_fixture(fixture_root)
            receipt_directory = Path(location) / "receipt"
            receipt_directory.mkdir(mode=0o700)
            receipt = receipt_directory / "local-inputs-receipt.json"
            inventory = fixture_root / "scripts/rc0_candidate/inventories/source-candidate-v1.json"
            cli_receipt = __import__("scripts.ci_local_receipt", fromlist=["run_local_input_gates"])
            cli_receipt.run_local_input_gates(fixture_root, receipt)
            arguments = final_arguments(str(receipt))
            arguments[6] = str(inventory)
            first = invoke_real(arguments, fixture_root)
            second = invoke_real(arguments, fixture_root)
            self.assertEqual(first[0], 0)
            self.assertTrue(first[1].startswith("FIXTURE_LOCAL_INPUTS_SATISFIED\n"))
            self.assertFalse(receipt.exists())
            self.assertEqual(second, (2, "BLOCKED(LOCAL_INPUTS_UNAVAILABLE)\n"))

    def test_fixture_summary_cannot_be_promoted_to_declaration_or_qualified(self):
        status, output, _ = invoke(final_arguments())
        self.assertEqual(status, 0)
        self.assertIn("RC0_QUALIFIED BLOCKED\n", output)
        self.assertIn("PRODUCTION_QUALIFICATION BLOCKED\n", output)
        self.assertIn("RELEASE_APPROVAL OUT_OF_SCOPE\n", output)
        self.assertIn("PUBLICATION_AUTHORIZATION OUT_OF_SCOPE\n", output)
        for forbidden in (" PASS", "gate_result", "VERDICT", "REPORT", "DECLARATION"):
            self.assertNotIn(forbidden, output)

        for control in ("--promote", "--declaration", "--report", "--trusted-key"):
            with self.subTest(control=control):
                status, output, validator = invoke(final_arguments() + [control])
                self.assertEqual((status, output), (2, ""))
                validator.assert_not_called()

    def test_external_capture_matrix_is_blocked_without_independent_provisioning(self):
        with tempfile.TemporaryDirectory() as location:
            fixture_root = Path(location) / "repository"
            self._receipt_fixture(fixture_root)
            receipt_directory = Path(location) / "receipt"
            receipt_directory.mkdir(mode=0o700)
            receipt = receipt_directory / "receipt.json"
            inventory = fixture_root / "scripts/rc0_candidate/inventories/source-candidate-v1.json"
            cli_receipt = __import__("scripts.ci_local_receipt", fromlist=["run_local_input_gates"])
            cli_receipt.run_local_input_gates(fixture_root, receipt)
            before = self._worktree_files(fixture_root)
            arguments = final_arguments(str(receipt))
            arguments[6] = str(inventory)
            status, output = invoke_real(arguments, fixture_root)
            after = self._worktree_files(fixture_root)
        self.assertEqual(status, 0)
        self.assertEqual(before, after)
        expected = {
            "EXTERNAL_CAPTURE ACCEPTED_ADRS BLOCKED(INDEPENDENT_VALIDATION_REQUIRED)",
            "EXTERNAL_CAPTURE POLICY BLOCKED(INDEPENDENT_PROVISIONING_REQUIRED)",
            "EXTERNAL_CAPTURE TRUST BLOCKED(INDEPENDENT_PROVISIONING_REQUIRED)",
            "EXTERNAL_CAPTURE ANTI_ROLLBACK BLOCKED(INDEPENDENT_PROVISIONING_REQUIRED)",
            "EXTERNAL_CAPTURE CURRENT_SOURCE BLOCKED(INDEPENDENT_CAPTURE_REQUIRED)",
            "EXTERNAL_CAPTURE RUNNER BLOCKED(INDEPENDENT_PROVISIONING_REQUIRED)",
            "EXTERNAL_INTERFACE docs/release/RC0_TRUST_ROOT_INTERFACE.md",
        }
        self.assertTrue(expected.issubset(set(output.splitlines())))
        self.assertNotIn("verification-report.json", output)

    @staticmethod
    def _worktree_files(root):
        return {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if ".git" not in path.relative_to(root).parts
        }

    @staticmethod
    def _receipt_fixture(root):
        (root / "scripts/rc0_candidate/inventories").mkdir(parents=True)
        (root / "docs/rc0").mkdir(parents=True)
        for relative in (
            "scripts/rc0_candidate/inventories/source-candidate-v1.json",
            "scripts/rc0_candidate/inventories/local-reliability-v1.json",
            "scripts/rc0_candidate/inventories/phase3-v1.json",
            "docs/rc0/taxonomy-migration-v1.json",
        ):
            shutil.copy2(ROOT / relative, root / relative)
        (root / "scripts/ci-local-inputs.sh").write_text("#!/bin/sh\nexit 0\n")
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        (root / ".git").chmod(0o700)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email", "fixture@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "Fixture"], check=True
        )
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "--quiet", "-m", "fixture"], check=True
        )


if __name__ == "__main__":
    unittest.main()
