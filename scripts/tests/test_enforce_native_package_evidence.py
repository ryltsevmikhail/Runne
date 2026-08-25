"""Fail-closed tests for native package evidence enforcement."""

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.enforce_native_package_evidence import main, validate


def valid_evidence() -> dict[str, object]:
    return {
        "schema_version": "desktop-native-platform-foundation.v1",
        "platform_id": "ubuntu-22.04-x86_64",
        "disposition": "verified",
        "blocker_code": None,
        "package_present": True,
        "native_operations": {operation: {"status": "verified"} for operation in (
            "install", "discover-installed-artifact", "executable-identity", "protected-launch",
            "protected-relaunch", "secure-store-writer-reader", "secure-store-third-process-deny",
            "signing-notarization", "uninstall",
        )},
        "artifact_sha256": "a" * 64,
        "source_ref": "b" * 40,
        "runner": {
            "instance_id": "runner-1", "job_id": "job-1", "workflow_run_id": "run-1",
            "image_sha256": "c" * 64, "boot_measurement_sha256": "d" * 64,
            "admission_sha256": "e" * 64,
        },
    }


class NativePackageEvidenceEnforcementTests(unittest.TestCase):
    def test_verified_evidence_is_accepted(self) -> None:
        self.assertEqual(validate(valid_evidence()), [])

    def test_linux_signing_not_applicable_is_accepted_only_for_that_operation(self) -> None:
        value = valid_evidence()
        value["native_operations"]["signing-notarization"] = {
            "status": "not_applicable",
            "detail": "platform has no signing or notarization gate",
        }
        self.assertEqual(validate(value), [])
        value["native_operations"]["install"] = {"status": "not_applicable"}
        self.assertTrue(validate(value))

    def test_blocked_or_incomplete_evidence_is_rejected(self) -> None:
        for mutation in (
            {"blocker_code": "RUNNER_TRUST_UNVERIFIED"},
            {"package_present": False},
            {"native_operations": {"install": {"status": "blocked"}}},
            {"native_operations": {}},
            {"native_operations": None},
        ):
            value = valid_evidence()
            value.update(mutation)
            with self.subTest(mutation=mutation):
                self.assertTrue(validate(value))

    def test_invalid_json_and_synthetic_evidence_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native-package.json"
            path.write_text("not json", encoding="utf-8")
            package = Path(directory) / "package.bin"
            package.write_bytes(b"package")
            bundle = Path(directory) / "attestation.jsonl"
            bundle.write_text("external proof", encoding="utf-8")
            common = ["--evidence", str(path), "--package", str(package), "--bundle", str(bundle),
                      "--repository", "https://git@git.sourcecraft.dev/ryltsevmg/runne.git",
                      "--workflow", "desktop-qualification", "--source-ref", "refs/tags/v1.0.0",
                      "--source-digest", "b" * 40, "--job-id", "job-1", "--workflow-run-id", "run-1"]
            self.assertNotEqual(main(common), 0)
            value = valid_evidence()
            value["artifact_sha256"] = hashlib.sha256(b"package").hexdigest()
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertNotEqual(main(common), 0)


if __name__ == "__main__":
    unittest.main()
