import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".sourcecraft/ci.yaml"
README = ROOT / ".sourcecraft/README.md"


class DesktopQualificationWorkflowTest(unittest.TestCase):
    def _qualification(self) -> str:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  desktop-qualification:", workflow)
        return workflow[workflow.index("  desktop-qualification:"):]

    def test_manual_qualification_has_exact_immutable_inputs_and_no_active_github_workflows(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        qualification = self._qualification()
        self.assertNotIn("desktop-qualification", workflow[workflow.index("on:"):workflow.index("env:")])
        self.assertIn("inputs:\n      protected_ref:\n        type: string\n        required: true\n        description: Immutable protected tag to qualify; policy accepts only refs/tags/v1.0.0.", qualification)
        self.assertIn("candidate_sha:\n        type: string\n        required: true", qualification)
        self.assertFalse((ROOT / ".github/workflows").exists())

    def test_compute_policy_precedes_all_native_and_evidence_tasks(self):
        qualification = self._qualification()
        policy = qualification[qualification.index("- name: qualification-policy"):qualification.index("- name: qualification-structural")]
        self.assertIn("image: python:3.12-slim", policy)
        for condition in (
            'test "$SOURCECRAFT_EVENT" = "manual"',
            'test "$SOURCECRAFT_COMMIT_REF" = "$QUALIFICATION_PROTECTED_REF"',
            'test "$SOURCECRAFT_COMMIT_SHA" = "$QUALIFICATION_CANDIDATE_SHA"',
            'test "$SOURCECRAFT_REPO_URL" = "https://git@git.sourcecraft.dev/ryltsevmg/runne.git"',
            "grep -Eq '^[0-9a-f]{40}$'",
        ):
            self.assertIn(condition, policy)
        for task, tag in (
            ("qualification-native-macos", "gocode-macos-arm64"),
            ("qualification-native-windows", "gocode-windows-x86_64"),
            ("qualification-evidence", "gocode-macos-arm64"),
        ):
            start = qualification.index(f"- name: {task}")
            section = qualification[start:]
            self.assertIn("needs: [qualification-policy]", section[:section.index("cubes:")])
            self.assertIn(f"runs_on: [self-hosted, {tag}]", section[:section.index("cubes:")])

    def test_linux_native_gate_builds_ubuntu_packages_on_pinned_compute(self):
        qualification = self._qualification()
        start = qualification.index("- name: qualification-native-linux")
        linux = qualification[start:qualification.index("- name: qualification-native-macos")]
        for value in (
            "needs: [qualification-policy]",
            "image: rust:1.97.1",
            'test "$(node --version)" = "v22.14.0"',
            "ca-certificates curl libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf python3 xz-utils",
            "node-v${NODE_VERSION}-linux-x64.tar.xz",
            "69b09dba5c8dcb05c4e4273a4340db1005abeafe3927efda2bc5b249e80437ec",
            "pnpm@11.10.0",
            "pnpm install --frozen-lockfile",
            "cargo test -p runne-platform-desktop -p runne-secure-store --all-targets --locked",
            "pnpm --filter @runne/desktop tauri build --bundles appimage,deb",
            "native_package_probe.py preflight --platform-pair ubuntu-22.04-x86_64",
            "package_smoke.py --platform ubuntu-22.04-x86_64",
        ):
            self.assertIn(value, linux)
        self.assertNotIn("exit 1", linux)

    def test_desktop_frontend_uses_pinned_node_and_pnpm(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        frontend = workflow[workflow.index("  desktop-frontend:"):workflow.index("  desktop-qualification:")]
        self.assertIn("image: node:22.14.0", frontend)
        self.assertNotIn("image: node:22\n", frontend)
        self.assertIn("pnpm@11.10.0", frontend)

    def test_native_workers_pin_node_pnpm_and_run_platform_package_smoke(self):
        qualification = self._qualification()
        for task, platform in (
            ("qualification-native-macos", "macos-13-arm64"),
            ("qualification-native-macos-x86_64", "macos-13-x86_64"),
            ("qualification-native-windows", "windows-10-22h2-x86_64"),
        ):
            start = qualification.index(f"- name: {task}")
            end = qualification.find("\n      - name: ", start + 1)
            section = qualification[start:] if end == -1 else qualification[start:end]
            for value in (
                'test "$(node --version)" = "v22.14.0"',
                'npm install --prefix "$SOURCECRAFT_WORKSPACE/.ci-tools" pnpm@11.10.0',
                'test "$(pnpm --version)" = "11.10.0"',
                f"python3 scripts/desktop/package_smoke.py --platform {platform}",
                "native_package_probe.py preflight",
            ):
                self.assertIn(value, section)

    def test_qualification_excludes_unsupported_legacy_import_but_keeps_native_packages(self):
        qualification = self._qualification()
        jobs = [line.strip().removeprefix("- name: ") for line in qualification.splitlines()
                if line.startswith("      - name: ")]
        self.assertNotIn("qualification-native-macos-legacy-cleanup", jobs)
        for job in ("qualification-native-macos", "qualification-native-macos-x86_64",
                    "qualification-native-linux", "qualification-native-windows"):
            self.assertIn(job, jobs)

    def test_native_release_tasks_require_real_signing_bootstrap(self):
        qualification = self._qualification()
        for task in ("qualification-native-macos", "qualification-native-macos-x86_64"):
            start = qualification.index(f"- name: {task}")
            end = qualification.find("\n      - name: ", start + 1)
            section = qualification[start:] if end == -1 else qualification[start:end]
            self.assertIn("prepare-macos-signing.sh", section)
            for name in (
                "APPLE_CERTIFICATE",
                "APPLE_CREDENTIAL_SERVICE_PROVISIONING_PROFILE",
                "APPLE_SIGNING_IDENTITY",
                "APPLE_PASSWORD",
                "APPLE_TEAM_ID",
            ):
                self.assertIn(name, section)
        bootstrap = (
            ROOT / "scripts/sourcecraft/prepare-macos-signing.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("RUNNE_CREDENTIAL_SERVICE_PROVISIONING_PROFILE", bootstrap)
        windows_start = qualification.index("- name: qualification-native-windows")
        windows_end = qualification.find("\n      - name: ", windows_start + 1)
        windows = qualification[windows_start:] if windows_end == -1 else qualification[windows_start:windows_end]
        self.assertIn("invoke-windows-signed-tauri-build.ps1 -Bundles nsis", windows)
        for name in ("WINDOWS_CERTIFICATE", "WINDOWS_CERTIFICATE_PASSWORD", "WINDOWS_CERTIFICATE_THUMBPRINT"):
            self.assertIn(name, windows)

    def test_qualification_covers_both_required_macos_architectures(self):
        qualification = self._qualification()
        self.assertIn("- name: qualification-native-macos-x86_64", qualification)
        self.assertIn("runs_on: [self-hosted, gocode-macos-x86_64]", qualification)
        self.assertIn("package_smoke.py --platform macos-13-x86_64", qualification)

    def test_native_tasks_run_with_provisioned_identity_and_enforce_probe_evidence(self):
        qualification = self._qualification()
        for task, platform in (
            ("qualification-native-linux", "ubuntu-22.04-x86_64"),
            ("qualification-native-macos", "macos-13-arm64"),
            ("qualification-native-macos-x86_64", "macos-13-x86_64"),
            ("qualification-native-windows", "windows-10-22h2-x86_64"),
        ):
            start = qualification.index(f"- name: {task}")
            end = qualification.find("\n      - name: ", start + 1)
            section = qualification[start:] if end == -1 else qualification[start:end]
            probe_run = (
                "run-linux-native-package-probe.sh"
                if task == "qualification-native-linux"
                else f"run --platform-pair {platform} --package \"$NATIVE_PACKAGE_PATH\""
            )
            for value in (
                "SOURCECRAFT_NATIVE_RUNNER_IDENTITY_PATH",
                "SOURCECRAFT_NATIVE_RUNNER_TRUST_ROOT_PATH",
                "SOURCECRAFT_NATIVE_RUNNER_TRUST_ROOT_SHA256",
                "SOURCECRAFT_NATIVE_ATTESTATION_BUNDLE_PATH",
                "NATIVE_PACKAGE_PATH=\"$(python3 -c",
                "recompute_package_path",
                f"preflight --platform-pair {platform} --package \"$NATIVE_PACKAGE_PATH\"",
                probe_run,
                "--evidence \"$NATIVE_EVIDENCE_PATH\"",
                "--job-id \"$SOURCECRAFT_TASK\"",
                "--workflow-run-id \"$SOURCECRAFT_RUN_ID\"",
                "/opt/gocode/sourcecraft/bin/sourcecraft-native-package-evidence-enforce",
                "--package \"$NATIVE_PACKAGE_PATH\" --bundle \"$SOURCECRAFT_NATIVE_ATTESTATION_BUNDLE_PATH\"",
            ):
                self.assertIn(value, section)

    def test_protected_evidence_uses_sourcecraft_policy_and_preserves_missing_evidence_blockers(self):
        qualification = self._qualification()
        evidence = qualification[qualification.index("- name: qualification-evidence"):]
        for value in (
            "SOURCECRAFT_DESKTOP_ATTEST_REPOSITORY: ${{ secrets.SOURCECRAFT_DESKTOP_ATTEST_REPOSITORY }}",
            "SOURCECRAFT_DESKTOP_ATTEST_WORKFLOW: ${{ secrets.SOURCECRAFT_DESKTOP_ATTEST_WORKFLOW }}",
            "SOURCECRAFT_DESKTOP_ATTEST_SOURCE_REF: ${{ secrets.SOURCECRAFT_DESKTOP_ATTEST_SOURCE_REF }}",
            "SOURCECRAFT_DESKTOP_ATTEST_SIGNER: ${{ secrets.SOURCECRAFT_DESKTOP_ATTEST_SIGNER }}",
            "/opt/gocode/sourcecraft/bin/sourcecraft-desktop-evidence-enforce --root \"$SOURCECRAFT_WORKSPACE\" --kind performance",
            "/opt/gocode/sourcecraft/bin/sourcecraft-desktop-evidence-enforce --root \"$SOURCECRAFT_WORKSPACE\" --kind qualification-matrices",
            "/opt/gocode/sourcecraft/bin/sourcecraft-desktop-evidence-enforce --root \"$SOURCECRAFT_WORKSPACE\" --kind visual-goldens",
            "qualification evidence attestation bundle",
            "visual golden attestation bundle",
        ):
            self.assertIn(value, evidence)
        self.assertNotIn("SOURCECRAFT_DESKTOP_ATTEST_VERIFY_KEY", qualification)
        for forbidden in ("github", "gh ", "GITHUB_", "actions/"):
            self.assertNotIn(forbidden, qualification.lower() if forbidden == "github" else qualification)

    def test_readme_declares_sourcecraft_as_sole_ci_and_github_archive_as_historical(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("единственный CI/CD", readme)
        self.assertIn("desktop-qualification", readme)
        self.assertIn("manual", readme)
        self.assertIn("gocode-macos-arm64", readme)
        self.assertIn("gocode-windows-x86_64", readme)
        self.assertIn(".github/workflows.disabled", readme)
        self.assertIn("исторический архив", readme)
        self.assertNotIn("Не перенесено из GitHub Actions", readme)

    def test_local_ci_runs_sourcecraft_qualification_contract(self):
        local_inputs = (ROOT / "scripts/ci-local-inputs.sh").read_text(encoding="utf-8")
        self.assertIn(
            '"$trusted_python" -m unittest scripts.desktop.tests.test_desktop_qualification_workflow -v',
            local_inputs,
        )
        self.assertNotIn(
            '"$trusted_python" -m unittest scripts.tests.test_desktop_qualification_workflow -v',
            local_inputs,
        )


if __name__ == "__main__":
    unittest.main()
