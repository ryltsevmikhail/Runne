"""Fail-closed tests for the native package probe."""
import os
import shutil
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
from scripts.desktop.enforce_native_package_evidence import validate as validate_native_evidence
from scripts.desktop.package_artifact_snapshot import stage_artifact
class NativePackageProbeTests(unittest.TestCase):
    def _run_rejected_package(self, root: Path, package: str) -> tuple[dict, list[tuple]]:
        evidence = root / "evidence.json"
        calls: list[tuple] = []
        preflight = {
            "platform_id": "ubuntu-22.04-x86_64",
            "disposition": "blocked",
            "blocker_code": "LINUX_SECURE_IDENTITY_UNVERIFIED",
            "detail": "preflight passed",
        }
        with (
            patch("scripts.desktop.native_package_probe.ROOT", root),
            patch("scripts.desktop.native_package_probe.recompute_package_path", return_value=package),
            patch("scripts.desktop.native_package_probe.preflight", return_value=preflight),
            patch("scripts.desktop.native_package_probe.native_probe", side_effect=lambda *args: calls.append(args)),
        ):
            run("ubuntu-22.04-x86_64", package, evidence)
        return __import__("json").loads(evidence.read_text(encoding="utf-8")), calls

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
    def test_run_records_sourcecraft_commit_sha_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"SOURCECRAFT_COMMIT_SHA": "a" * 40, "LEGACY_CI_COMMIT_SHA": "b" * 40},
            clear=False,
        ):
            evidence = Path(directory) / "evidence.json"
            run("ubuntu-22.04-x86_64", None, evidence)
            value = __import__("json").loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(value["source_ref"], "a" * 40)
    def test_recompute_package_path_matches_bundle_convention(self) -> None:
        self.assertEqual(
            recompute_package_path("windows-10-22h2-x86_64"),
            recompute_package_path("windows-10-22h2-x86_64", "nsis"),
        )

    def test_required_package_paths_cover_every_mandatory_artifact(self) -> None:
        from scripts.desktop import native_package_probe

        self.assertTrue(hasattr(native_package_probe, "required_package_paths"))
        self.assertEqual(
            native_package_probe.required_package_paths("macos-13-arm64"),
            {"app", "dmg"},
        )
        self.assertEqual(
            native_package_probe.required_package_paths("windows-10-22h2-x86_64"),
            {"nsis"},
        )
        self.assertEqual(
            native_package_probe.required_package_paths("ubuntu-22.04-x86_64"),
            {"appimage", "deb"},
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
            root = Path(directory)
            package = root / "Runne.app"; package.mkdir()
            (root / "Runne.dmg").write_text("package", encoding="utf-8")
            evidence = root / "evidence.json"
            calls = []
            with patch("scripts.desktop.native_package_probe.preflight", return_value={
                "platform_id": "macos-13-arm64", "disposition": "blocked",
                "blocker_code": "MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED", "detail": "preflight passed",
            }), patch("scripts.desktop.native_package_probe.ROOT", root), patch(
                "scripts.desktop.native_package_probe.recompute_package_path",
                side_effect=lambda _pair, bundle=None: {"app": "Runne.app", "dmg": "Runne.dmg"}[bundle or "app"],
            ), patch("scripts.desktop.native_package_probe.native_probe", side_effect=lambda *args: calls.append(args) or {"status": "verified"}):
                run("macos-13-arm64", "Runne.app", evidence)
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
            value = __import__("json").loads(evidence.read_text(encoding="utf-8"))
            self.assertIn("RUNNER_TRUST_UNVERIFIED", evidence.read_text(encoding="utf-8"))
            self.assertTrue(validate_native_evidence(value))

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

    def test_run_rejects_traversal_before_hash_or_native_operations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value, calls = self._run_rejected_package(Path(directory), "../outside.deb")
        self.assertIn("PACKAGE_ARTIFACT_PATH_UNSAFE", value["detail"])
        self.assertFalse(value["package_present"])
        self.assertIsNone(value["artifact_sha256"])
        self.assertEqual(calls, [])

    def test_run_rejects_parent_symlink_before_hash_or_native_operations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"; external = Path(directory) / "external"
            root.mkdir(); external.mkdir(); (external / "Runne.deb").write_text("artifact", encoding="utf-8")
            (root / "bundle").symlink_to(external, target_is_directory=True)
            value, calls = self._run_rejected_package(root, "bundle/Runne.deb")
        self.assertIn("PACKAGE_ARTIFACT_PATH_UNSAFE", value["detail"])
        self.assertFalse(value["package_present"])
        self.assertIsNone(value["artifact_sha256"])
        self.assertEqual(calls, [])

    def test_run_rejects_final_symlink_before_hash_or_native_operations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "actual.deb").write_text("artifact", encoding="utf-8")
            (root / "Runne.deb").symlink_to(root / "actual.deb")
            value, calls = self._run_rejected_package(root, "Runne.deb")
        self.assertIn("PACKAGE_ARTIFACT_PATH_UNSAFE", value["detail"])
        self.assertFalse(value["package_present"])
        self.assertIsNone(value["artifact_sha256"])
        self.assertEqual(calls, [])

    def test_run_rejects_wrong_bundle_type_before_hash_or_native_operations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "Runne.deb").mkdir()
            value, calls = self._run_rejected_package(root, "Runne.deb")
        self.assertIn("PACKAGE_ARTIFACT_TYPE_INVALID", value["detail"])
        self.assertFalse(value["package_present"])
        self.assertIsNone(value["artifact_sha256"])
        self.assertEqual(calls, [])

    def test_run_uses_staged_snapshot_when_source_swaps_after_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, external = root / "Runne.deb", root / "external.deb"
            source.write_bytes(b"admitted"); external.write_bytes(b"external")
            (root / "Runne.AppImage").write_bytes(b"companion")
            evidence = root / "evidence.json"; calls: list[str] = []
            def probe(_pair: str, _operation: str, package: str, *_lease_args: object) -> dict[str, str]:
                calls.append(package)
                if len(calls) == 1:
                    source.unlink(); source.symlink_to(external)
                return {"status": "verified"}
            previous = Path.cwd(); os.chdir(root)
            try:
                with patch("scripts.desktop.native_package_probe.ROOT", root), patch(
                    "scripts.desktop.native_package_probe.recompute_package_path",
                    side_effect=lambda _pair, bundle=None: {"deb": "Runne.deb", "appimage": "Runne.AppImage"}[bundle or "deb"],
                ), patch("scripts.desktop.native_package_probe.preflight", return_value={
                    "platform_id": "ubuntu-22.04-x86_64", "disposition": "blocked",
                    "blocker_code": "LINUX_SECURE_IDENTITY_UNVERIFIED", "detail": "preflight passed",
                }), patch("scripts.desktop.native_package_probe.native_probe", side_effect=probe):
                    run("ubuntu-22.04-x86_64", "Runne.deb", evidence)
            finally:
                os.chdir(previous)
            value = __import__("json").loads(evidence.read_text(encoding="utf-8"))
        self.assertTrue(calls)
        self.assertTrue(all(Path(path).resolve() != external.resolve() for path in calls))
        self.assertEqual(value["artifact_sha256"], __import__("hashlib").sha256(b"admitted").hexdigest())

    def test_staged_artifact_cannot_be_replaced_before_cleanup(self) -> None:
        if os.name != "posix": self.skipTest("POSIX mode-bit invariant")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Runne.deb"
            source.write_bytes(b"admitted")
            snapshot = stage_artifact(root, "Runne.deb", "deb")
            try:
                self.assertEqual(snapshot.path.parent.stat().st_mode & 0o222, 0)
                if getattr(os, "geteuid", lambda: -1)() != 0: self.assertRaises(PermissionError, snapshot.path.unlink)
                self.assertEqual(snapshot.path.read_bytes(), b"admitted")
            finally:
                snapshot.close()

    def test_pinned_snapshot_survives_staging_root_replacement(self) -> None:
        from scripts.desktop.native_package_probe import artifact_sha256

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Runne.deb").write_bytes(b"admitted")
            snapshot = stage_artifact(root, "Runne.deb", "deb")
            staging_root = snapshot.staging_root
            moved_root = staging_root.with_name(f"{staging_root.name}-moved")
            try:
                staging_root.rename(moved_root)
                staging_root.mkdir()
                (staging_root / "artifact").write_bytes(b"replacement")
                self.assertEqual(artifact_sha256(snapshot.path), __import__("hashlib").sha256(b"admitted").hexdigest())
                self.assertEqual(snapshot.path.read_bytes(), b"admitted")
            finally:
                snapshot.close()
            try:
                self.assertTrue(staging_root.is_dir())
                self.assertEqual((staging_root / "artifact").read_bytes(), b"replacement")
                if moved_root.exists():
                    self.assertEqual(list(moved_root.iterdir()), [])
            finally:
                shutil.rmtree(staging_root, ignore_errors=True)
                if moved_root.exists():
                    moved_root.chmod(0o700)
                    shutil.rmtree(moved_root, ignore_errors=True)

    def test_native_probe_rejects_unpinned_package_path(self) -> None:
        from scripts.desktop.native_package_probe import native_probe

        with patch("scripts.desktop.native_package_probe.subprocess.run") as execute:
            result = native_probe("ubuntu-22.04-x86_64", "install", "/tmp/artifact.deb")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["detail"], "PACKAGE_ARTIFACT_SNAPSHOT_LEASE_REQUIRED")
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
