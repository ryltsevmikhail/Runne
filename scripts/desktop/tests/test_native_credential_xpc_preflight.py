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
from scripts.desktop.native_credential_enrollment.macos_preflight import (
    ENVELOPE_FIELDS,
    PROTECTED_SUBJECT_DIGEST_FIELDS,
)
from scripts.desktop.tests.test_native_credential_xpc_qualification import _expected, _row, _selector

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
        **{field: "d" * 64 for field in PROTECTED_SUBJECT_DIGEST_FIELDS},
        "started_at": "2026-09-06T11:00:00Z", "finished_at": "2026-09-06T11:30:00Z",
        "cleanup_verified": True,
        "signature": {"algorithm": "ed25519", "value": base64.b64encode(b"x" * 64).decode()},
    }


class XpcPreflightTests(unittest.TestCase):
    def test_envelope_fields_match_the_protected_verifier(self):
        import ast

        source = (ROOT / "tools/sourcecraft-native-qualification/verifier.py").read_text()
        assignment = next(
            node for node in ast.parse(source).body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "ENVELOPE" for target in node.targets)
        )
        self.assertEqual(ENVELOPE_FIELDS, ast.literal_eval(assignment.value))

    def test_full_external_envelope_shape_has_a_structural_fixture(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope

        golden = json.loads((ROOT / "docs/golden/macos-xpc-service-external-contract-v1.json").read_text())
        files = golden["files"]
        receipt = files["signed-envelope.json"]
        self.assertEqual(set(receipt), ENVELOPE_FIELDS)
        fixture_now = datetime.strptime(golden["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        fixture_context = {key: receipt[key] for key in ("source_revision", "workflow_run_id", "namespace_sha256", "signer_key_id")}
        self.assertEqual(validate_envelope(receipt, files["macos-13-arm64.json"], files["expected-tuples.json"], fixture_context, fixture_now), [])

    def test_external_fixture_rejects_tampered_or_missing_redacted_receipts(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope

        golden = json.loads((ROOT / "docs/golden/macos-xpc-service-external-contract-v1.json").read_text())
        files = golden["files"]
        receipt = files["signed-envelope.json"]
        fixture_now = datetime.strptime(golden["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        fixture_context = {key: receipt[key] for key in ("source_revision", "workflow_run_id", "namespace_sha256", "signer_key_id")}
        for mutate in (
            lambda row: row.pop("code_identities"),
            lambda row: row["artifact_scan"].pop("scan_subject_sha256"),
            lambda row: row["selectors"]["clean_install"].update(ticket_sha256="d" * 64),
        ):
            with self.subTest(mutate=mutate):
                row = copy.deepcopy(files["macos-13-arm64.json"])
                mutate(row)
                self.assertTrue(validate_envelope(receipt, row, files["expected-tuples.json"], fixture_context, fixture_now))

    def test_external_fixture_rejects_self_consistent_receipt_from_another_run(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope

        golden = json.loads((ROOT / "docs/golden/macos-xpc-service-external-contract-v1.json").read_text())
        files = golden["files"]
        receipt = files["signed-envelope.json"]
        fixture_now = datetime.strptime(golden["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        fixture_context = {key: receipt[key] for key in ("source_revision", "workflow_run_id", "namespace_sha256", "signer_key_id")}
        row = copy.deepcopy(files["macos-13-arm64.json"])
        row["selectors"]["clean_install"] = _selector("clean_install", "another-run")
        self.assertTrue(validate_envelope(receipt, row, files["expected-tuples.json"], fixture_context, fixture_now))

    def test_fake_signed_envelope_can_only_pass_structural_validation(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope
        self.assertEqual(validate_envelope(envelope(), _row(), _expected(), context(), NOW), [])

    def test_signature_encoding_cannot_be_confused_with_native_paths(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope
        value = envelope()
        value["signature"]["value"] = base64.urlsafe_b64encode(b"\xff" * 64).decode()
        self.assertEqual(validate_envelope(value, _row(), _expected(), context(), NOW), [])

    def test_protected_subject_digest_shapes_fail_closed(self):
        from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope

        for field in PROTECTED_SUBJECT_DIGEST_FIELDS:
            with self.subTest(field=field):
                receipt = envelope()
                receipt[field] = "d" * 63
                self.assertTrue(validate_envelope(receipt, _row(), _expected(), context(), NOW))

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
