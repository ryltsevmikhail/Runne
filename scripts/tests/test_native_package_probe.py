"""Fail-closed tests for the native package probe."""

import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts.desktop.native_package_probe import (
    PAIR_MATRIX,
    preflight,
    recompute_package_path,
    run,
)


class NativePackageProbeTests(unittest.TestCase):
    def test_preflight_unknown_pair_is_blocked(self) -> None:
        result = preflight("beos-x86")
        self.assertEqual(result["disposition"], "blocked")
        self.assertEqual(result["blocker_code"], "RUNNER_TRUST_UNVERIFIED")

    def test_preflight_rejects_host_mismatch(self) -> None:
        # On any single host, three of the four pairs necessarily mismatch.
        blocked = 0
        for pair in PAIR_MATRIX:
            result = preflight(pair)
            if result["disposition"] == "blocked":
                blocked += 1
        self.assertGreaterEqual(blocked, 3)

    def test_preflight_is_deterministic(self) -> None:
        self.assertEqual(preflight("macos-13-arm64"), preflight("macos-13-arm64"))

    def test_preflight_rejects_declared_package_path_that_differs_from_tauri_config(self) -> None:
        result = preflight("ubuntu-22.04-x86_64", "target/release/bundle/deb/wrong.deb")
        self.assertEqual(result["blocker_code"], "RUNNER_TRUST_UNVERIFIED")
        self.assertIn("package path", result["detail"])

    def test_run_emits_blocked_for_absent_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            run("macos-13-arm64", None, evidence)
            text = evidence.read_text(encoding="utf-8")
            self.assertIn('"blocked"', text)
            # Host mismatch vs. absent package both stay fail-closed; the exact
            # blocker code is host-dependent and covered by the vocabulary test.
            self.assertTrue(
                "MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED" in text
                or "RUNNER_TRUST_UNVERIFIED" in text
            )

    def test_run_marks_absent_package_false(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            run("ubuntu-22.04-x86_64", None, evidence)
            text = evidence.read_text(encoding="utf-8")
            self.assertIn('"package_present": false', text)

    def test_recompute_package_path_matches_bundle_convention(self) -> None:
        self.assertEqual(
            recompute_package_path("windows-10-22h2-x86_64"),
            recompute_package_path("windows-10-22h2-x86_64", "nsis"),
        )

    def test_version_matches_macos_major_and_ubuntu_exact(self) -> None:
        from scripts.desktop.native_package_probe import _version_matches
        self.assertTrue(_version_matches("13.5.0", (13,)))
        self.assertFalse(_version_matches("14.1.0", (13,)))
        self.assertTrue(_version_matches("22.04", "22.04"))
        self.assertFalse(_version_matches("26.04", "22.04"))
        self.assertFalse(_version_matches("22.04", "22.04."))

    def test_existing_package_still_requires_native_install_and_identity_probes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "Runne.app"
            package.write_text("package", encoding="utf-8")
            evidence = Path(directory) / "evidence.json"
            calls = []
            with patch("scripts.desktop.native_package_probe.preflight", return_value={
                "platform_id": "macos-13-arm64", "disposition": "blocked",
                "blocker_code": "MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED", "detail": "preflight passed",
            }), patch("scripts.desktop.native_package_probe.native_probe", side_effect=lambda *args: calls.append(args) or {"status": "verified"}):
                run("macos-13-arm64", str(package), evidence)
            value = __import__("json").loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(value["disposition"], "blocked")
            self.assertTrue(calls)
            self.assertIn("install", value["native_operations"])
            self.assertIn("secure-store-third-process-deny", value["native_operations"])

    def test_macos_bundle_directory_has_a_deterministic_artifact_digest(self) -> None:
        from scripts.desktop.native_package_probe import artifact_sha256
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Runne.app"; bundle.mkdir()
            (bundle / "Contents").mkdir(); (bundle / "Contents" / "Info.plist").write_text("bundle", encoding="utf-8")
            self.assertRegex(artifact_sha256(bundle), r"^[0-9a-f]{64}$")

    def test_run_rejects_missing_verified_runner_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            run("ubuntu-22.04-x86_64", None, evidence, None)
            self.assertIn("RUNNER_TRUST_UNVERIFIED", evidence.read_text(encoding="utf-8"))

    def test_run_rejects_identity_with_mismatched_admission_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence, identity = Path(directory) / "evidence.json", Path(directory) / "identity.json"
            admission = {"instance_id": "runner", "image_sha256": "a" * 64, "boot_measurement_sha256": "b" * 64, "job_id": "other", "workflow_run_id": "run", "issued_at": "2026-08-14T00:00:00Z"}
            identity.write_text(__import__("json").dumps({"schema_version": "desktop-native-runner-identity.v1", "verified": True, "platform_id": "ubuntu-22.04-x86_64", "job_id": "job", "workflow_run_id": "run", "admission": admission, "admission_sha256": __import__("hashlib").sha256(__import__("json").dumps(admission, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}), encoding="utf-8")
            run("ubuntu-22.04-x86_64", None, evidence, identity)
            self.assertIsNone(__import__("json").loads(evidence.read_text(encoding="utf-8"))["runner"]["instance_id"])

    def test_run_rejects_forged_identity_even_with_matching_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence, identity, root = Path(directory) / "evidence.json", Path(directory) / "identity.json", Path(directory) / "root.pem"
            root.write_text("not a public key", encoding="utf-8")
            admission = {"schema_version": "desktop-native-runner-admission.v1", "platform_id": "ubuntu-22.04-x86_64", "job_id": "job", "workflow_run_id": "run", "instance_id": "runner", "image_sha256": "a" * 64, "boot_measurement_sha256": "b" * 64, "issued_at": "2026-08-14T00:00:00Z", "expires_at": "2026-08-14T01:00:00Z", "signature_algorithm": "RSA-SHA256", "signature": "Zm9yZ2Vk"}
            identity.write_text(__import__("json").dumps({"schema_version": "desktop-native-runner-identity.v1", "verified": True, "platform_id": "ubuntu-22.04-x86_64", "job_id": "job", "workflow_run_id": "run", "admission": admission, "admission_sha256": __import__("hashlib").sha256(__import__("json").dumps(admission, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "trust_root_sha256": __import__("hashlib").sha256(root.read_bytes()).hexdigest()}), encoding="utf-8")
            run("ubuntu-22.04-x86_64", None, evidence, identity, root, __import__("hashlib").sha256(root.read_bytes()).hexdigest())
            self.assertIsNone(__import__("json").loads(evidence.read_text(encoding="utf-8"))["runner"]["instance_id"])

    def test_run_binds_identity_to_external_job_and_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence, identity, root = Path(directory) / "evidence.json", Path(directory) / "identity.json", Path(directory) / "root.pem"
            root.write_text("root", encoding="utf-8")
            identity.write_text(__import__("json").dumps({"job_id": "old-job", "workflow_run_id": "old-run", "admission": {"instance_id": "runner"}}), encoding="utf-8")
            with patch("scripts.desktop.native_package_probe.verify_admission_identity", return_value=False) as verify:
                run("ubuntu-22.04-x86_64", None, evidence, identity, root, "a" * 64, "new-job", "new-run")
            self.assertEqual(verify.call_args.args[-2:], ("new-job", "new-run"))


if __name__ == "__main__":
    unittest.main()
