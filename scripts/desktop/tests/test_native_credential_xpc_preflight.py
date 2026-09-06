"""Deterministic envelope/preflight tests, using explicitly fake signatures."""
import base64
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.desktop.native_credential_enrollment.macos_bindings import canonical_digest
from scripts.desktop.tests.test_native_credential_xpc_qualification import _row, _expected

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[3]


def context():
    return {"source_revision": "a" * 40, "workflow_run_id": "isolated-macos-run-1",
            "namespace_sha256": "b" * 64, "signer_key_id": "c" * 64}


def envelope():
    return {
        "schema_version": "macos-xpc-service-signed-envelope.v1",
        **context(), "row_sha256": canonical_digest(_row()),
        "expected_tuples_sha256": canonical_digest(_expected()),
        "started_at": "2026-09-06T11:00:00Z", "finished_at": "2026-09-06T11:30:00Z",
        "cleanup_verified": True,
        "signature": {"algorithm": "ed25519", "value": base64.b64encode(b"x" * 64).decode()},
    }


class XpcPreflightTests(unittest.TestCase):
    def test_fake_signed_envelope_can_only_pass_structural_validation(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope
        self.assertEqual(validate_envelope(envelope(), _row(), _expected(), context(), NOW), [])

    def test_signature_encoding_cannot_be_confused_with_native_paths(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope
        value = envelope()
        value["signature"]["value"] = base64.urlsafe_b64encode(b"\xff" * 64).decode()
        self.assertEqual(validate_envelope(value, _row(), _expected(), context(), NOW), [])

    def test_stale_future_wrong_run_and_changed_subject_fail_closed(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope
        for key, value in (
            ("started_at", "2026-09-04T11:00:00Z"), ("finished_at", "2026-09-04T11:30:00Z"),
            ("finished_at", "2026-09-07T11:30:00Z"), ("started_at", "2026-09-06T11:45:00Z"),
            ("source_revision", "d" * 40), ("workflow_run_id", "another-run"),
            ("namespace_sha256", "d" * 64), ("row_sha256", "d" * 64),
            ("expected_tuples_sha256", "d" * 64), ("signer_key_id", "d" * 64),
            ("cleanup_verified", False), ("signature", {"algorithm": "none", "value": ""}),
        ):
            with self.subTest(key=key):
                receipt = envelope()
                receipt[key] = value
                self.assertTrue(validate_envelope(receipt, _row(), _expected(), context(), NOW))

    def test_missing_duplicate_and_secret_envelope_fields_rejected(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope
        for key in envelope():
            receipt = envelope()
            del receipt[key]
            self.assertTrue(validate_envelope(receipt, _row(), _expected(), context(), NOW))
        receipt = envelope()
        receipt["secret"] = "do-not-log"
        errors = validate_envelope(receipt, _row(), _expected(), context(), NOW)
        self.assertTrue(errors)
        self.assertNotIn("do-not-log", repr(errors))

    def test_cli_preflight_is_deterministic_and_never_executes_native_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tuples, run = root / "tuples.json", root / "run.json"
            tuples.write_text(json.dumps(_expected()))
            run.write_text(json.dumps(context()))
            command = [sys.executable, str(ROOT / "scripts/desktop/native_credential_xpc_preflight.py"),
                       "preflight", "--expected-tuples", str(tuples), "--run-context", str(run)]
            outputs = []
            for _ in range(2):
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(json.loads(result.stdout))
            self.assertEqual(outputs[0], outputs[1])
            self.assertFalse(outputs[0]["qualified"])
            self.assertFalse(outputs[0]["native_execution"])
            self.assertTrue(outputs[0]["external_signature_verification_required"])
            run.write_text('{"workflow_run_id":"a","workflow_run_id":"b"}')
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stdout)["qualified"])

    def test_deployment_and_each_code_identity_are_exactly_bound(self):
        from scripts.desktop.native_credential_enrollment import macos
        for field in ("desktop", "writer", "daemon", "service"):
            row = _row()
            row["deployment"]["entitlements"][field]["keychain-access-groups"] = [
                "758F9Z45SR.com.runne.credential-service", "shared",
            ]
            self.assertTrue(macos.validate_row(row))
        for field in _row()["deployment"]:
            row = _row()
            row["deployment"].pop(field)
            self.assertTrue(macos.validate_row(row))
        for field in _row()["tuple"]:
            row, expected = _row(), copy.deepcopy(_expected())
            row["tuple"][field] = "e" * 64
            self.assertTrue(macos.validate_expected_tuples(expected, [row]))


if __name__ == "__main__":
    unittest.main()
