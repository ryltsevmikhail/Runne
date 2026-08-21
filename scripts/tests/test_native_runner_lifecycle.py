"""Fail-closed tests for the native runner lifecycle verifier."""

import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from scripts.desktop.native_runner_lifecycle import BLOCKER, _request_completion, verify_admission, verify_admission_identity, verify_completion, verify_completion_attestation


def signed(value: dict[str, object], directory: Path, bits: int = 3072) -> tuple[dict[str, object], Path]:
    """Sign the canonical control-plane payload with an ephemeral test key."""
    private, public, payload, signature = (directory / name for name in ("private.pem", "public.pem", "payload.json", "signature.bin"))
    value.setdefault("signature_algorithm", "RSA-SHA256")
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", str(private), "-pkeyopt", f"rsa_keygen_bits:{bits}"], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
    payload.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(payload)], check=True, capture_output=True)
    value["signature"] = base64.b64encode(signature.read_bytes()).decode()
    return value, public


class NativeRunnerLifecycleTests(unittest.TestCase):
    def test_control_plane_request_requires_file_bearer_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "oidc-token"
            self.assertIsNone(_request_completion("https://control-plane.invalid", [], 1, token))

    def test_control_plane_request_sends_file_bearer_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "oidc-token"; token.write_text("oidc-token", encoding="utf-8")
            class Response:
                status = 200
                def __enter__(self): return self
                def __exit__(self, *args): return None
                def read(self): return b'{"ok":true}'
            with patch("scripts.desktop.native_runner_lifecycle.urllib.request.urlopen", return_value=Response()) as open_url:
                self.assertEqual(_request_completion("https://control-plane.invalid", [], 1, token), {"ok": True})
            self.assertEqual(open_url.call_args.args[0].get_header("Authorization"), "Bearer oidc-token")
    def test_admission_identity_rejects_weak_key_and_absurd_ttl(self) -> None:
        now = datetime.now(UTC)
        admission = {"schema_version": "desktop-native-runner-admission.v1", "platform_id": "MACOS-13-ARM64", "job_id": "job", "workflow_run_id": "run", "instance_id": "runner", "image_sha256": "a" * 64, "boot_measurement_sha256": "b" * 64, "issued_at": (now - timedelta(minutes=1)).isoformat(), "expires_at": "2999-01-01T00:00:00+00:00"}
        with tempfile.TemporaryDirectory() as directory:
            admission, root = signed(admission, Path(directory), bits=1024)
            identity = {"schema_version": "desktop-native-runner-identity.v1", "verified": True, "platform_id": "MACOS-13-ARM64", "job_id": "job", "workflow_run_id": "run", "admission": admission, "admission_sha256": hashlib.sha256(json.dumps(admission, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "trust_root_sha256": hashlib.sha256(root.read_bytes()).hexdigest()}
            self.assertFalse(verify_admission_identity(identity, str(root), hashlib.sha256(root.read_bytes()).hexdigest(), "MACOS-13-ARM64", "job", "run"))

    def test_root_swap_after_single_read_cannot_verify_alternate_signature(self) -> None:
        now = datetime.now(UTC)
        claim = {"schema_version": "desktop-native-runner-admission.v1", "platform_id": "MACOS-13-ARM64", "job_id": "job", "workflow_run_id": "run", "instance_id": "runner", "image_sha256": "a" * 64, "boot_measurement_sha256": "b" * 64, "issued_at": (now - timedelta(minutes=1)).isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat()}
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            _, pinned = signed(dict(claim), Path(first)); admission, alternate = signed(dict(claim), Path(second))
            root = Path(first) / "root.pem"; root.write_bytes(pinned.read_bytes()); digest = hashlib.sha256(root.read_bytes()).hexdigest()
            identity = {"schema_version": "desktop-native-runner-identity.v1", "verified": True, "platform_id": "MACOS-13-ARM64", "job_id": "job", "workflow_run_id": "run", "admission": admission, "admission_sha256": hashlib.sha256(json.dumps(admission, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "trust_root_sha256": digest}
            original = Path.read_bytes
            def swap(path: Path) -> bytes:
                value = original(path)
                if path == root: root.write_bytes(alternate.read_bytes())
                return value
            with patch.object(Path, "read_bytes", swap):
                self.assertFalse(verify_admission_identity(identity, str(root), digest, "MACOS-13-ARM64", "job", "run"))
    def test_missing_control_plane_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rows = Path(directory) / "rows"
            rows.mkdir()
            (rows / "provisional-macos-13-arm64.json").write_text("{}", encoding="utf-8")
            output = Path(directory) / "lifecycle.json"
            verify_completion(rows, None, None, None, None, output)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(value["verified"])
            self.assertEqual(value["disposition"], "blocked")
            self.assertEqual(value["blocker_code"], BLOCKER)

    def test_absent_trust_root_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rows = Path(directory) / "rows"
            rows.mkdir()
            output = Path(directory) / "lifecycle.json"
            verify_completion(rows, "https://control-plane.invalid", None, None, None, output)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(value["verified"])
            self.assertEqual(value["blocker_code"], BLOCKER)

    def test_unreachable_control_plane_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rows = Path(directory) / "rows"
            rows.mkdir()
            output = Path(directory) / "lifecycle.json"
            verify_completion(rows, "https://127.0.0.1:1/unreachable", "root", None, None, output, wait_seconds=1)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(value["verified"])
            self.assertEqual(value["blocker_code"], BLOCKER)

    def test_empty_rows_dir_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rows = Path(directory) / "rows"
            rows.mkdir()
            output = Path(directory) / "lifecycle.json"
            verify_completion(rows, None, None, None, None, output)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(value["rows"], [])
            self.assertFalse(value["verified"])

    def test_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rows = Path(directory) / "rows"
            rows.mkdir()
            (rows / "a.json").write_text("{}", encoding="utf-8")
            (rows / "b.json").write_text("{}", encoding="utf-8")
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            verify_completion(rows, None, None, None, None, first)
            verify_completion(rows, None, None, None, None, second)
            self.assertEqual(first.read_text(encoding="utf-8"), second.read_text(encoding="utf-8"))

    def test_signed_completion_binds_every_runner_fact(self) -> None:
        rows = [
            {"platform_id": "MACOS-13-ARM64", "runner": {
                "instance_id": "instance-1", "image_sha256": "a" * 64,
                "boot_measurement_sha256": "b" * 64, "job_id": "job-1", "workflow_run_id": "run-1", "admission_sha256": "c" * 64, "admission_issued_at": "2026-08-13T23:00:00Z", "admission_expires_at": "2026-08-14T01:00:00Z",
            }},
        ]
        payload = {"schema_version": "desktop-native-runner-lifecycle.v1", "completion": [
            {"instance_id": "instance-1", "image_sha256": "a" * 64,
             "boot_measurement_sha256": "b" * 64, "job_id": "job-1",
             "workflow_run_id": "run-1", "admission_sha256": "c" * 64,
             "action": "destroyed", "job_completed_at": "2026-08-13T23:30:00Z", "completed_at": "2026-08-14T00:00:00Z"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            payload, root = signed(payload, Path(directory))
            observed_at = datetime(2026, 8, 14, 0, 30, tzinfo=UTC)
            self.assertEqual(verify_completion_attestation(payload, str(root), hashlib.sha256(root.read_bytes()).hexdigest(), rows, observed_at), [])
            payload["completion"][0]["job_id"] = "job-2"
            self.assertTrue(verify_completion_attestation(payload, str(root), hashlib.sha256(root.read_bytes()).hexdigest(), rows, observed_at))

    def test_completion_rejects_wrong_workflow_run_or_expired_fact(self) -> None:
        rows = [{"platform_id": "MACOS-13-ARM64", "disposition": "verified", "runner": {"instance_id": "i", "image_sha256": "a" * 64, "boot_measurement_sha256": "b" * 64, "job_id": "job", "workflow_run_id": "run", "admission_sha256": "c" * 64, "admission_issued_at": "2020-01-01T00:00:00Z", "admission_expires_at": "2020-01-01T01:00:00Z"}}]
        payload = {"schema_version": "desktop-native-runner-lifecycle.v1", "completion": [{"instance_id": "i", "image_sha256": "a" * 64, "boot_measurement_sha256": "b" * 64, "job_id": "job", "workflow_run_id": "other", "admission_sha256": "c" * 64, "action": "destroyed", "job_completed_at": "2020-01-01T00:00:00Z", "completed_at": "2020-01-01T00:00:00Z"}]}
        with tempfile.TemporaryDirectory() as directory:
            payload, root = signed(payload, Path(directory))
            self.assertTrue(verify_completion_attestation(payload, str(root), hashlib.sha256(root.read_bytes()).hexdigest(), rows))

    def test_completion_rejects_future_fact(self) -> None:
        rows = [{"platform_id": "MACOS-13-ARM64", "disposition": "verified", "runner": {"instance_id": "i", "image_sha256": "a" * 64, "boot_measurement_sha256": "b" * 64, "job_id": "job", "workflow_run_id": "run", "admission_sha256": "c" * 64, "admission_issued_at": "2026-08-13T23:00:00Z", "admission_expires_at": "2026-08-14T01:00:00Z"}}]
        payload = {"schema_version": "desktop-native-runner-lifecycle.v1", "completion": [{"instance_id": "i", "image_sha256": "a" * 64, "boot_measurement_sha256": "b" * 64, "job_id": "job", "workflow_run_id": "run", "admission_sha256": "c" * 64, "action": "destroyed", "job_completed_at": "2026-08-14T00:00:00Z", "completed_at": "2999-01-01T00:00:00Z"}]}
        with tempfile.TemporaryDirectory() as directory:
            payload, root = signed(payload, Path(directory))
            self.assertTrue(verify_completion_attestation(payload, str(root), hashlib.sha256(root.read_bytes()).hexdigest(), rows))

    def test_admission_requires_public_key_signed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "identity.json"
            self.assertEqual(verify_admission("https://127.0.0.1:1", "public-root", None, None, "MACOS-13-ARM64", "job", "run", output, wait_seconds=1), 0)
            self.assertFalse(json.loads(output.read_text(encoding="utf-8"))["verified"])


if __name__ == "__main__":
    unittest.main()
