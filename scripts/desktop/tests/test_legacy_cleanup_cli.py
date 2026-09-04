"""Execute the structural CLI; no native operations or qualification."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.tests.test_legacy_cleanup_evidence import evidence

ROOT = Path(__file__).resolve().parents[3]


class LegacyCleanupCliTests(unittest.TestCase):
    def run_cli(self, payload, candidate="a" * 64):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sensitive-canary.json"
            if payload is not None:
                path.write_text(payload)
            return subprocess.run([
                sys.executable, "-m", "scripts.desktop.legacy_cleanup_evidence_probe",
                "--evidence", str(path), "--candidate-sha256", candidate,
                "--tuple-sha256", "b" * 64, "--workflow-run-id", "isolated-run-1",
            ], cwd=ROOT, capture_output=True, text=True, check=False)

    def test_valid_structure_is_never_qualification(self):
        result = self.run_cli(json.dumps(evidence()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "qualified": False, "structurally_valid": True, "errors": [],
        })

    def test_duplicate_malformed_missing_and_foreign_evidence_fail_redacted(self):
        valid = json.dumps(evidence())
        for payload, candidate in [(None, "a" * 64), ("sensitive-canary", "a" * 64),
                                   (" " * 65537, "a" * 64), ("NaN", "a" * 64),
                                   ("[" * 2000 + "]" * 2000, "a" * 64),
                                   (valid[:-1] + ', "schema_version": "duplicate"}', "a" * 64),
                                   (valid, "d" * 64)]:
            result = self.run_cli(payload, candidate)
            self.assertEqual(result.returncode, 1)
            output = json.loads(result.stdout)
            self.assertFalse(output["qualified"])
            self.assertFalse(output["structurally_valid"])
            self.assertNotIn("sensitive-canary", result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stdout + result.stderr)
