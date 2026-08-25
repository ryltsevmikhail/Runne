import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.desktop.performance_budget import _metrics_digest, validate_measurements


ROOT = Path(__file__).resolve().parents[3]


class PerformanceBudgetTest(unittest.TestCase):
    @staticmethod
    def _valid_measurements():
        return {
            "schema_version": "desktop-performance-measurements.v2",
            "source_ref": "refs/tags/v1.0.0",
            "source_digest": "a" * 40,
            "producer": "protected-runner",
            "artifact_sha256": "0" * 64,
            "measured_at": "2026-08-24T12:00:00Z",
            "runner": {"id": "native-runner", "image_sha256": "b" * 64},
            "metrics": {
                "shell_p75": {"value": 1200, "unit": "ms"}, "navigation_p95": {"value": 90, "unit": "ms"},
                "event_to_render_p95": {"value": 40, "unit": "ms"}, "timeline_fps": {"value": 60, "unit": "fps"},
                "renderer_idle_memory": {"value": 200, "unit": "MiB"}, "timeline_10k_memory": {"value": 400, "unit": "MiB"},
                "compressed_js": {"value": 1.5, "unit": "MiB"}, "critical_flow_long_task": {"value": 90, "unit": "ms"},
            },
        }

    def test_synthetic_runner_temp_measurement_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "measurements.json"
            path.write_text(json.dumps(self._valid_measurements()), encoding="utf-8")
            result = subprocess.run([sys.executable, "scripts/desktop/performance_budget.py", "--measurements", str(path), "--bundle", str(path) + ".intoto.jsonl", "--verify-external", "--source-ref", "refs/tags/v1.0.0", "--source-digest", "a" * 40], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("canonical", result.stdout)

    def test_trusted_canonical_measurement_requires_attested_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "docs/evidence/desktop-qualification/desktop-performance-measurements.json"
            path.parent.mkdir(parents=True)
            measurements = self._valid_measurements()
            measurements["artifact_sha256"] = _metrics_digest(measurements["metrics"])
            path.write_text(json.dumps(measurements), encoding="utf-8")
            bundle = path.with_name(path.name + ".intoto.jsonl")
            bundle.write_text("bundle\n", encoding="utf-8")
            policy = {"repository": "https://git@git.sourcecraft.dev/org/repo.git", "workflow": "desktop-qualification", "source_ref": "refs/tags/v1.0.0", "signer": "desktop-release-attestor"}
            with patch("scripts.desktop.performance_budget.verify_attestation", return_value={"verified": True}) as verifier:
                errors = validate_measurements(path, source_ref="refs/tags/v1.0.0", source_digest="a" * 40, verify_external=True, bundle=bundle, root=root, policy=policy)

        self.assertEqual(errors, [])
        self.assertEqual(verifier.call_args.args[3], "a" * 40)

    def test_rejects_a_measurement_with_the_wrong_unit(self):
        """Changing navigation from milliseconds to an unbounded unit must fail."""
        measurements = {
            "schema_version": "desktop-performance-measurements.v1",
            "source_ref": "a" * 40,
            "measured_at": "2026-08-24T12:00:00Z",
            "runner": {"id": "native-runner", "image_sha256": "b" * 64},
            "metrics": {
                "shell_p75": {"value": 1200, "unit": "ms"},
                "navigation_p95": {"value": 90, "unit": "seconds"},
                "event_to_render_p95": {"value": 40, "unit": "ms"},
                "timeline_fps": {"value": 60, "unit": "fps"},
                "renderer_idle_memory": {"value": 200, "unit": "MiB"},
                "timeline_10k_memory": {"value": 400, "unit": "MiB"},
                "compressed_js": {"value": 1.5, "unit": "MiB"},
                "critical_flow_long_task": {"value": 90, "unit": "ms"},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "measurements.json"
            path.write_text(json.dumps(measurements), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "scripts/desktop/performance_budget.py", "--measurements", str(path), "--source-ref", "refs/tags/v1.0.0", "--source-digest", "a" * 40],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("navigation_p95: unit must be ms", result.stdout)

    def test_rejects_missing_metrics_and_budget_exceedance(self):
        """Omitting event timing or exceeding the shell bound must not pass as measured."""
        measurements = {
            "schema_version": "desktop-performance-measurements.v1",
            "source_ref": "a" * 40,
            "measured_at": "2026-08-24T12:00:00Z",
            "runner": {"id": "native-runner", "image_sha256": "b" * 64},
            "metrics": {
                "shell_p75": {"value": 1501, "unit": "ms"},
                "navigation_p95": {"value": 90, "unit": "ms"},
                "timeline_fps": {"value": 60, "unit": "fps"},
                "renderer_idle_memory": {"value": 200, "unit": "MiB"},
                "timeline_10k_memory": {"value": 400, "unit": "MiB"},
                "compressed_js": {"value": 1.5, "unit": "MiB"},
                "critical_flow_long_task": {"value": 90, "unit": "ms"},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "measurements.json"
            path.write_text(json.dumps(measurements), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "scripts/desktop/performance_budget.py", "--measurements", str(path), "--source-ref", "refs/tags/v1.0.0", "--source-digest", "a" * 40],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("metrics: missing event_to_render_p95", result.stdout)
        self.assertIn("shell_p75: exceeds maximum 1500 ms", result.stdout)

    def test_requires_the_candidate_source_ref(self):
        """A measurement cannot pass without an explicit candidate binding."""
        result = subprocess.run(
            [sys.executable, "scripts/desktop/performance_budget.py", "--measurements", "missing.json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--source-ref", result.stderr)

    def test_rejects_a_non_sha_candidate_source_ref(self):
        """A symbolic or shortened candidate ref cannot bind measurements."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "measurements.json"
            path.write_text("{}", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "scripts/desktop/performance_budget.py", "--measurements", str(path), "--source-ref", "refs/tags/v1.0.0", "--source-digest", "candidate"],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("source_digest must be a full commit SHA", result.stdout)


if __name__ == "__main__":
    unittest.main()
