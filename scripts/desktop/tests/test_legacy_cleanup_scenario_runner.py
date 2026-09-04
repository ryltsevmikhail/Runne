"""Runner gates: host preconditions and evidence validation, never qualified."""
import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.desktop import legacy_cleanup_scenario_runner as runner
from scripts.desktop.tests.test_legacy_cleanup_evidence import evidence


class LegacyCleanupScenarioRunnerTests(unittest.TestCase):
    def test_evidence_input_is_bounded_before_json_decoding(self):
        # A slice after read_bytes still allocates an unbounded external file.
        sizes = []

        class ObservedInput(io.BytesIO):
            def read(self, size=-1):
                sizes.append(size)
                return super().read(size)

        source = ObservedInput(b" " * (runner.MAX_EVIDENCE_BYTES + 2))
        with mock.patch.object(Path, "open", return_value=source):
            with self.assertRaises(ValueError):
                runner.load_evidence(Path("unused-evidence.json"))
        self.assertEqual(sizes, [runner.MAX_EVIDENCE_BYTES + 1])

    def test_check_host_requires_darwin_arm64_and_opt_in(self):
        with mock.patch.object(runner, "host_is_isolated_darwin_arm64", return_value=False):
            self.assertEqual(runner.check_host(True),
                             ["legacy scenario host is not darwin arm64"])
        with mock.patch.object(runner, "host_is_isolated_darwin_arm64", return_value=True):
            self.assertEqual(runner.check_host(False),
                             ["isolated disposable host opt-in is missing"])
            self.assertEqual(runner.check_host(True), [])

    def test_valid_envelope_passes_structurally_and_is_never_qualified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(evidence()))
            errors = runner.validate_evidence_file(
                path, "a" * 64, "b" * 64, "isolated-run-1",
            )
        self.assertEqual(errors, [])

    def test_missing_malformed_oversized_and_foreign_envelopes_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            malformed = Path(directory) / "malformed.json"
            malformed.write_text("{not json")
            oversized = Path(directory) / "oversized.json"
            oversized.write_text(" " * (runner.MAX_EVIDENCE_BYTES + 1))
            foreign = Path(directory) / "foreign.json"
            bound_elsewhere = {**evidence(), "candidate_sha256": "d" * 64}
            foreign.write_text(json.dumps(bound_elsewhere))
            for path in (missing, malformed, oversized, foreign):
                errors = runner.validate_evidence_file(
                    path, "a" * 64, "b" * 64, "isolated-run-1",
                )
                self.assertTrue(errors, path)
                self.assertFalse(any("canary" in error for error in errors))

    def test_cli_check_host_and_validate_modes_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(evidence()))
            with mock.patch.object(runner, "host_is_isolated_darwin_arm64",
                                   return_value=True), \
                 mock.patch("sys.stdout"):
                self.assertEqual(
                    runner.main(["check-host", "--isolated-host"]), 0)
                self.assertEqual(runner.main(["check-host"]), 1)
                self.assertEqual(runner.main([
                    "validate-evidence", "--evidence", str(path),
                    "--candidate-sha256", "a" * 64, "--tuple-sha256", "b" * 64,
                    "--workflow-run-id", "isolated-run-1",
                ]), 0)
                self.assertEqual(runner.main([
                    "validate-evidence", "--evidence", str(path),
                    "--candidate-sha256", "d" * 64, "--tuple-sha256", "b" * 64,
                    "--workflow-run-id", "isolated-run-1",
                ]), 1)

    def test_check_host_rejects_foreign_user_and_signed_in_icloud(self):
        with mock.patch.object(runner, "host_is_isolated_darwin_arm64", return_value=True), \
             mock.patch.object(runner, "current_user", return_value="runne-qualification"), \
             mock.patch.object(runner, "icloud_account_present", return_value=False):
            self.assertEqual(runner.check_host(True, "runne-qualification"), [])
            self.assertEqual(
                runner.check_host(True, "someone-else"),
                ["legacy scenario host user is not the disposable account"],
            )
        with mock.patch.object(runner, "host_is_isolated_darwin_arm64", return_value=True), \
             mock.patch.object(runner, "current_user", return_value="runne-qualification"), \
             mock.patch.object(runner, "icloud_account_present", return_value=True):
            self.assertEqual(
                runner.check_host(True, "runne-qualification"),
                ["legacy scenario host has a signed-in iCloud account"],
            )

    def test_pinned_scenario_contract_names_are_stable(self):
        self.assertEqual(runner.__doc__ and "legacy_cleanup_scenario_chain"
                         in runner.__doc__, True)
        self.assertIn("RUNNE_LEGACY_CLEANUP_EVIDENCE", runner.__doc__)

    def test_rust_producer_envelope_shape_is_accepted_by_the_validator(self):
        selectors = (
            "authorized_import", "durable_cutover", "replacement_denied",
            "ambiguous_source_denied", "exact_source_deleted",
            "restart_after_delete_before_confirmation", "reimport_denied",
        )
        receipts = ",".join(
            '"{0}":{{"observation_sha256":"{1}","status":"verified"}}'.format(
                name, "0" * 63 + "1")
            for name in selectors
        )
        envelope = (
            '{{"candidate_sha256":"{0}",'
            '"schema_version":"legacy-source-cleanup-evidence.v1",'
            '"selectors":{{{1}}},'
            '"tuple_sha256":"{2}",'
            '"workflow_run_id":"isolated-run-1"}}'
        ).format("a" * 64, receipts, "b" * 64)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rust-envelope.json"
            path.write_text(envelope)
            errors = runner.validate_evidence_file(
                path, "a" * 64, "b" * 64, "isolated-run-1",
            )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
