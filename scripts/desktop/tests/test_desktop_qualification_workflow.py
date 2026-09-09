import unittest
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".sourcecraft/ci.yaml"
README = ROOT / ".sourcecraft/README.md"
BRANCH_POLICY = ROOT / ".sourcecraft/branches.yaml"


class DesktopQualificationWorkflowTest(unittest.TestCase):
    def _qualification(self) -> str:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  desktop-qualification:", workflow)
        return workflow[workflow.index("  desktop-qualification:") :]

    def _task(self, name: str) -> str:
        qualification = self._qualification()
        start = qualification.index(f"- name: {name}")
        end = qualification.find("\n      - name: ", start + 1)
        return qualification[start:] if end == -1 else qualification[start:end]

    def test_manual_policy_binds_immutable_semver_tag_and_exact_sha(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        qualification = self._qualification()
        self.assertNotIn(
            "desktop-qualification", workflow[workflow.index("on:") : workflow.index("env:")]
        )
        for value in (
            "candidate_sha:\n        type: string\n        required: true",
            'test "$SOURCECRAFT_EVENT" = "manual"',
            "^refs/tags/v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$",
            'test "$SOURCECRAFT_COMMIT_SHA" = "$QUALIFICATION_CANDIDATE_SHA"',
            'test "$SOURCECRAFT_REPO_URL" = "https://git@git.sourcecraft.dev/ryltsevmg/runne.git"',
            "grep -Eq '^[0-9a-f]{40}$'",
        ):
            self.assertIn(value, qualification)
        self.assertNotIn("protected_ref:", qualification)
        self.assertIn("`.sourcecraft/branches.yaml`", README.read_text(encoding="utf-8"))
        policy = BRANCH_POLICY.read_text(encoding="utf-8")
        for value in ('target: tag', 'matches: "v*"', 'prevent_creation', 'prevent_update', 'prevent_deletion'):
            self.assertIn(value, policy)
        self.assertFalse((ROOT / ".github/workflows").exists())

    def test_native_pair_matches_canonical_platform_scope(self):
        decision = json.loads(
            (ROOT / "docs/decisions/v1-platform-scope-v1.json").read_text(encoding="utf-8")
        )
        supported = {
            f"macos-{scope['os_version']}-arm64"
            for scope in decision["platform_scopes"]
            if scope["os_family"] == "macOS" and scope["architecture"] == "arm64"
        }
        qualification = self._qualification()
        self.assertEqual(supported, {"macos-14-arm64"})
        self.assertIn("--platform macos-14-arm64", qualification)
        self.assertNotIn("macos-13-arm64", qualification)

    def test_d1_1a_workflow_has_policy_structural_arm64_and_release_evidence_tasks(self):
        qualification = self._qualification()
        jobs = [
            line.strip().removeprefix("- name: ")
            for line in qualification.splitlines()
            if line.startswith("      - name: ")
        ]
        self.assertEqual(
            jobs,
            [
                "qualification-policy",
                "qualification-structural",
                "qualification-native-macos",
                "qualification-evidence",
            ],
        )
        native = self._task("qualification-native-macos")
        self.assertIn("needs: [qualification-policy]", native)
        self.assertIn("runs_on: [self-hosted, gocode-macos-arm64]", native)
        for forbidden in (
            "gocode-macos-x86_64",
            "gocode-windows-x86_64",
            "ubuntu-22.04-x86_64",
            "windows-10-22h2-x86_64",
        ):
            self.assertNotIn(forbidden, qualification)

    def test_release_evidence_remains_runner_owned_and_fail_closed(self):
        evidence = self._task("qualification-evidence")
        self.assertIn("needs: [qualification-policy]", evidence)
        self.assertIn("runs_on: [self-hosted, gocode-macos-arm64]", evidence)
        for value in (
            "/opt/gocode/sourcecraft/bin/sourcecraft-desktop-evidence-enforce",
            "--kind performance",
            "--kind qualification-matrices",
            "--kind visual-goldens",
            "BLOCKED: protected performance measurement",
            "BLOCKED: qualification evidence attestation bundle",
            "BLOCKED: visual golden attestation bundle",
        ):
            self.assertIn(value, evidence)

    def test_xpc_contracts_run_in_structural_task(self):
        structural = self._task("qualification-structural")
        for name in (
            "apt-get install -y --no-install-recommends git ca-certificates",
            'git config --global --add safe.directory "$SOURCECRAFT_WORKSPACE"',
            "test_native_credential_xpc_hardening",
            "test_native_credential_xpc_preflight",
            "test_native_credential_xpc_qualification",
            "test_native_credential_enrollment",
            "test_native_credential_xpc_external_contract",
            "test_native_credential_counter_types",
            "test_native_credential_xpc_schema",
            "tools/sourcecraft-native-qualification/tests/test_conformance.py",
            "tools/sourcecraft-native-qualification/tests/test_controller.py",
            "scripts/requirements-schema-tests.txt",
        ):
            self.assertIn(name, structural)
        install = structural.index("apt-get install -y --no-install-recommends git ca-certificates")
        checkout = structural.index('cd "$SOURCECRAFT_WORKSPACE"')
        trust = structural.index('git config --global --add safe.directory "$SOURCECRAFT_WORKSPACE"')
        tests = structural.index("python3 -m unittest")
        self.assertLess(install, checkout)
        self.assertLess(checkout, trust)
        self.assertLess(trust, tests)

    def test_arm64_native_task_requires_signed_package_and_external_authority(self):
        native = self._task("qualification-native-macos")
        for value in (
            "prepare-macos-signing.sh",
            'test "$(node --version)" = "v22.14.0"',
            'npm install --prefix "$SOURCECRAFT_WORKSPACE/.ci-tools" pnpm@11.10.0',
            "pnpm install --frozen-lockfile",
            "credential_service_package_observation_surface --locked",
            "tauri build --bundles app,dmg",
            "package_smoke.py --platform macos-14-arm64",
            "SOURCECRAFT_NATIVE_ATTESTATION_BUNDLE_PATH",
            "/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-controller",
            "/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-request-signature",
            "/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-verifier",
            "/private/var/run/gocode/sourcecraft-native-qualification-sign.sock",
            "/private/etc/gocode/sourcecraft-native-qualification/policy.json",
        ):
            self.assertIn(value, native)
        self.assertNotIn("native_package_probe.py run", native)
        for name in (
            "APPLE_CERTIFICATE",
            "APPLE_CREDENTIAL_SERVICE_PROVISIONING_PROFILE",
            "APPLE_SIGNING_IDENTITY",
            "APPLE_PASSWORD",
            "APPLE_TEAM_ID",
        ):
            self.assertIn(name, native)

    def test_readme_and_local_ci_describe_the_same_authority(self):
        readme = README.read_text(encoding="utf-8")
        for value in (
            "единственный CI/CD",
            "desktop-qualification",
            "manual",
            "gocode-macos-arm64",
            ".github/workflows.disabled",
            "исторический архив",
        ):
            self.assertIn(value, readme)
        local = (ROOT / "scripts/ci-local-inputs.sh").read_text(encoding="utf-8")
        self.assertIn(
            '"$trusted_python" -m unittest scripts.desktop.tests.test_desktop_qualification_workflow -v',
            local,
        )


if __name__ == "__main__":
    unittest.main()
