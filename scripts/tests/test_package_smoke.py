"""Fail-closed structural tests for Desktop package smoke checks."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/desktop/package_smoke.py"
SOURCECRAFT_WORKFLOW = ROOT / ".sourcecraft/ci.yaml"


class PackageSmokeTests(unittest.TestCase):
    def test_tauri_manifest_declares_production_identity_and_sidecar_staging(self) -> None:
        config = json.loads((ROOT / "apps/desktop/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
        package = json.loads((ROOT / "apps/desktop/package.json").read_text(encoding="utf-8"))
        self.assertEqual(config["identifier"], "com.runne.desktop")
        self.assertEqual(config["mainBinaryName"], "runne-desktop")
        self.assertEqual(config["bundle"]["externalBin"], ["binaries/runned", "binaries/runne"])
        self.assertEqual(config["bundle"]["macOS"]["minimumSystemVersion"], "13.0")
        self.assertTrue(config["bundle"]["macOS"]["hardenedRuntime"])
        self.assertFalse(config["bundle"]["windows"]["allowDowngrades"])
        self.assertEqual(config["bundle"]["windows"]["digestAlgorithm"], "sha256")
        self.assertIn("stage:bundled-daemon", config["build"]["beforeBuildCommand"])
        self.assertIn("stage:bundled-daemon", package["scripts"])
        staging = (ROOT / "scripts/desktop/stage_bundled_daemon.mjs").read_text(encoding="utf-8")
        for token in ("runne-daemon", "desktop-protected", "runned-", "CARGO_BUILD_TARGET"):
            self.assertIn(token, staging)

    def test_production_manifest_has_no_configuration_blockers(self) -> None:
        result = subprocess.run(
            ["python3", str(SCRIPT), "--platform", "ubuntu-22.04-x86_64"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertTrue(result.stdout)
        output = json.loads(result.stdout)
        self.assertNotIn("DEVELOPMENT_IDENTIFIER", output["blockers"])
        self.assertNotIn("BUNDLED_DAEMON_NOT_CONFIGURED", output["blockers"])
        self.assertIn(output["disposition"], {"blocked", "structurally_valid"})
        if output["disposition"] == "blocked":
            self.assertIn("PACKAGE_ARTIFACT_MISSING", output["blockers"])

    def test_release_policy_rejects_wrong_main_binary_or_downgrade_policy(self) -> None:
        from scripts.desktop import package_smoke

        config = json.loads((ROOT / "apps/desktop/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
        config["mainBinaryName"] = "wrong"
        self.assertIn("MAIN_BINARY_NAME_INVALID", package_smoke._manifest_blockers(config))
        config["mainBinaryName"] = "runne-desktop"
        config["bundle"]["windows"]["allowDowngrades"] = True
        self.assertIn("WINDOWS_RELEASE_POLICY_INVALID", package_smoke._manifest_blockers(config))

    def test_sourcecraft_qualification_is_manual_and_has_all_package_gates(self) -> None:
        workflow = SOURCECRAFT_WORKFLOW.read_text(encoding="utf-8")
        qualification = workflow[workflow.index("  desktop-qualification:"):]
        self.assertIn("inputs:", qualification)
        self.assertIn(
            "type: string\n"
            "        required: true\n"
            "        description: Immutable protected tag to qualify; policy accepts only refs/tags/v1.0.0.",
            qualification,
        )
        self.assertIn("candidate_sha:\n        type: string\n        required: true", qualification)
        self.assertNotIn("desktop-qualification", workflow[workflow.index("on:"):workflow.index("env:")])
        self.assertFalse((ROOT / ".github/workflows").exists())
        for task in (
            "qualification-native-macos",
            "qualification-native-macos-x86_64",
            "qualification-native-windows",
            "qualification-native-linux",
        ):
            self.assertIn(f"- name: {task}", qualification)
        self.assertIn("gocode-macos-arm64", qualification)
        self.assertIn("gocode-macos-x86_64", qualification)
        self.assertIn("gocode-windows-x86_64", qualification)
        self.assertIn("image: rust:1.97.1", qualification)
        self.assertIn("tauri build --bundles appimage,deb", qualification)
        self.assertIn("tauri build --bundles app,dmg", qualification)
        self.assertIn("invoke-windows-signed-tauri-build.ps1 -Bundles nsis", qualification)
        self.assertIn("prepare-macos-signing.sh", qualification)
        for secret in ("WINDOWS_CERTIFICATE", "WINDOWS_CERTIFICATE_PASSWORD", "WINDOWS_CERTIFICATE_THUMBPRINT"):
            self.assertIn(secret, qualification)
        self.assertIn('test "$(node --version)" = "v22.14.0"', qualification)
        self.assertIn('npm install --prefix "$SOURCECRAFT_WORKSPACE/.ci-tools" pnpm@11.10.0', qualification)
        self.assertIn('test "$(pnpm --version)" = "11.10.0"', qualification)
        self.assertIn("package_smoke.py --platform macos-13-arm64", qualification)
        self.assertIn("package_smoke.py --platform macos-13-x86_64", qualification)
        self.assertIn("package_smoke.py --platform windows-10-22h2-x86_64", qualification)
        self.assertIn("native_package_probe.py preflight --platform-pair ubuntu-22.04-x86_64", qualification)
        self.assertIn("package_smoke.py --platform ubuntu-22.04-x86_64", qualification)
        self.assertNotIn("SOURCECRAFT_DESKTOP_ATTEST_VERIFY_KEY", qualification)

    def test_sourcecraft_policy_runs_before_native_tasks_and_has_no_github_contract(self) -> None:
        workflow = SOURCECRAFT_WORKFLOW.read_text(encoding="utf-8")
        qualification = workflow[workflow.index("  desktop-qualification:"):]
        policy_start = qualification.index("- name: qualification-policy")
        structural_start = qualification.index("- name: qualification-structural")
        policy = qualification[policy_start:structural_start]
        self.assertIn('test "$SOURCECRAFT_EVENT" = "manual"', policy)
        self.assertIn('test "$SOURCECRAFT_COMMIT_REF" = "$QUALIFICATION_PROTECTED_REF"', policy)
        self.assertIn('test "$SOURCECRAFT_COMMIT_SHA" = "$QUALIFICATION_CANDIDATE_SHA"', policy)
        self.assertIn('test "$SOURCECRAFT_REPO_URL" = "https://git@git.sourcecraft.dev/ryltsevmg/runne.git"', policy)
        self.assertIn("grep -Eq '^[0-9a-f]{40}$'", policy)
        self.assertLess(policy_start, structural_start)
        for task in (
            "qualification-native-macos",
            "qualification-native-windows",
            "qualification-native-linux",
            "qualification-evidence",
        ):
            task_start = qualification.index(f"- name: {task}")
            task_header = qualification[task_start:qualification.index("cubes:", task_start)]
            self.assertIn("needs: [qualification-policy]", task_header)
            self.assertGreater(task_start, policy_start)
        for forbidden in ("GITHUB", "gh ", "actions/"):
            self.assertNotIn(forbidden, workflow)

    def test_unresolved_mandated_artifact_path_stays_blocked(self) -> None:
        from scripts.desktop import package_smoke

        with (
            patch.object(package_smoke, "_load_config", return_value={}),
            patch.object(package_smoke, "_manifest_blockers", return_value=[]),
            patch.object(package_smoke, "required_package_paths", return_value={"deb"}),
            patch.object(package_smoke, "recompute_package_path", return_value=None),
        ):
            result = package_smoke.smoke("ubuntu-22.04-x86_64")

        self.assertEqual(result["disposition"], "blocked")
        self.assertIn("PACKAGE_ARTIFACT_PATH_UNRESOLVED", result["blockers"])
        self.assertEqual(result["artifacts"]["deb"]["path"], None)

    def test_artifact_type_must_match_its_bundle_format(self) -> None:
        from scripts.desktop import package_smoke

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            with (
                patch.object(package_smoke, "ROOT", root),
                patch.object(package_smoke, "_load_config", return_value={}),
                patch.object(package_smoke, "_manifest_blockers", return_value=[]),
                patch.object(package_smoke, "recompute_package_path", return_value="artifact"),
            ):
                artifact.write_text("not an app bundle", encoding="utf-8")
                with patch.object(package_smoke, "required_package_paths", return_value={"app"}):
                    app_result = package_smoke.smoke("macos-13-arm64")
                artifact.unlink()
                artifact.mkdir()
                with patch.object(package_smoke, "required_package_paths", return_value={"dmg"}):
                    dmg_result = package_smoke.smoke("macos-13-arm64")

        self.assertEqual(app_result["disposition"], "blocked")
        self.assertEqual(dmg_result["disposition"], "blocked")
        self.assertIn("PACKAGE_ARTIFACT_TYPE_INVALID", app_result["blockers"])
        self.assertIn("PACKAGE_ARTIFACT_TYPE_INVALID", dmg_result["blockers"])

    def test_traversal_artifact_path_is_rejected_before_type_check(self) -> None:
        from scripts.desktop import package_smoke

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            with (
                patch.object(package_smoke, "ROOT", root),
                patch.object(package_smoke, "_load_config", return_value={}),
                patch.object(package_smoke, "_manifest_blockers", return_value=[]),
                patch.object(package_smoke, "required_package_paths", return_value={"deb"}),
                patch.object(package_smoke, "recompute_package_path", return_value="../outside.deb"),
            ):
                result = package_smoke.smoke("ubuntu-22.04-x86_64")

        self.assertEqual(result["disposition"], "blocked")
        self.assertIn("PACKAGE_ARTIFACT_PATH_UNSAFE", result["blockers"])

    def test_parent_symlink_to_external_regular_artifact_is_rejected(self) -> None:
        from scripts.desktop import package_smoke

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root, external = base / "root", base / "external"
            root.mkdir()
            external.mkdir()
            (external / "Runne.deb").write_text("artifact", encoding="utf-8")
            (root / "bundle").symlink_to(external, target_is_directory=True)
            with (
                patch.object(package_smoke, "ROOT", root),
                patch.object(package_smoke, "_load_config", return_value={}),
                patch.object(package_smoke, "_manifest_blockers", return_value=[]),
                patch.object(package_smoke, "required_package_paths", return_value={"deb"}),
                patch.object(package_smoke, "recompute_package_path", return_value="bundle/Runne.deb"),
            ):
                result = package_smoke.smoke("ubuntu-22.04-x86_64")

        self.assertEqual(result["disposition"], "blocked")
        self.assertIn("PACKAGE_ARTIFACT_PATH_UNSAFE", result["blockers"])

    def test_final_artifact_symlink_is_rejected(self) -> None:
        from scripts.desktop import package_smoke

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "actual.deb").write_text("artifact", encoding="utf-8")
            (root / "Runne.deb").symlink_to(root / "actual.deb")
            with (
                patch.object(package_smoke, "ROOT", root),
                patch.object(package_smoke, "_load_config", return_value={}),
                patch.object(package_smoke, "_manifest_blockers", return_value=[]),
                patch.object(package_smoke, "required_package_paths", return_value={"deb"}),
                patch.object(package_smoke, "recompute_package_path", return_value="Runne.deb"),
            ):
                result = package_smoke.smoke("ubuntu-22.04-x86_64")

        self.assertEqual(result["disposition"], "blocked")
        self.assertIn("PACKAGE_ARTIFACT_PATH_UNSAFE", result["blockers"])

    def test_app_bundle_with_nested_symlink_is_rejected(self) -> None:
        from scripts.desktop import package_smoke

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "Runne.app"
            app.mkdir()
            (root / "external").write_text("outside", encoding="utf-8")
            (app / "Contents").symlink_to(root / "external")
            with (
                patch.object(package_smoke, "ROOT", root),
                patch.object(package_smoke, "_load_config", return_value={}),
                patch.object(package_smoke, "_manifest_blockers", return_value=[]),
                patch.object(package_smoke, "required_package_paths", return_value={"app"}),
                patch.object(package_smoke, "recompute_package_path", return_value="Runne.app"),
            ):
                result = package_smoke.smoke("macos-13-arm64")

        self.assertEqual(result["disposition"], "blocked")
        self.assertIn("PACKAGE_ARTIFACT_PATH_UNSAFE", result["blockers"])


if __name__ == "__main__":
    unittest.main()
