import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "verify-secure-replay-desktop.sh"
REPOSITORY_ROOT = pathlib.Path(__file__).parents[2]


def bash_executable() -> str:
    executable = shutil.which("bash")
    if executable is None:
        raise RuntimeError("Bash executable is required")
    return executable


class VerifySecureReplayDesktopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = pathlib.Path(self.temporary_directory.name)
        self.bin_directory = self.root / "bin"
        self.bin_directory.mkdir()
        self.command_log = self.root / "commands.log"
        runner = self.bin_directory / "runner"
        runner.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "tool=${0##*/}\n"
            "{ printf '%s' \"$tool\"; for argument in \"$@\"; do printf ' <%s>' \"$argument\"; done; printf '\\n'; } >> \"$FAKE_COMMAND_LOG\"\n"
            "if [ \"${FAKE_FAIL_COMMAND:-}\" = \"$tool\" ]; then exit 73; fi\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        for tool in ("cargo", "git", "pnpm", "python3"):
            tool_path = self.bin_directory / tool
            shutil.copy2(runner, tool_path)
            tool_path.chmod(0o755)

    def run_verifier(
        self,
        *arguments: str,
        fail_command: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.bin_directory}{os.pathsep}{environment['PATH']}"
        environment["FAKE_COMMAND_LOG"] = str(self.command_log)
        environment["SECURE_REPLAY_TEST_SENTINEL"] = "must-not-be-printed"
        if fail_command is not None:
            environment["FAKE_FAIL_COMMAND"] = fail_command
        return subprocess.run(
            [bash_executable(), str(SCRIPT_PATH), *arguments],
            cwd=REPOSITORY_ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )

    def commands(self) -> list[str]:
        if not self.command_log.exists():
            return []
        return self.command_log.read_text(encoding="utf-8").splitlines()

    def assert_safe_output(self, result: subprocess.CompletedProcess[str]) -> None:
        combined = f"{result.stdout}\n{result.stderr}"
        self.assertNotIn("must-not-be-printed", combined)
        self.assertNotIn("SECURE_REPLAY_TEST_SENTINEL", combined)

    def test_missing_mode_is_rejected_before_child_gate(self) -> None:
        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected exactly one mode: runtime, frontend or all", result.stderr)
        self.assertEqual(self.commands(), [])
        self.assert_safe_output(result)

    def test_unknown_mode_is_rejected_before_child_gate(self) -> None:
        result = self.run_verifier("unknown")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected exactly one mode: runtime, frontend or all", result.stderr)
        self.assertEqual(self.commands(), [])
        self.assert_safe_output(result)

    def test_runtime_mode_dispatches_only_contract_and_daemon_e2e(self) -> None:
        result = self.run_verifier("runtime")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.commands(),
            [
                "cargo <run> <-p> <gocode-runtime> <--bin> <generate-ui-contract> <--locked> <--> <--check>",
                "python3 <scripts/verify_secure_replay_evidence.py> <--manifest> <docs/evidence/secure-replay-desktop-resume-v1.json> <--legacy-blob> <4713d84e94f68ae9c29de71325d4ecbd8d3096bb>",
                "python3 <scripts/verify_secure_replay_evidence.py> <--manifest> <docs/evidence/secure-replay-desktop-resume-v2.json> <--base> <d4dbabff8272118d99e6388dfbbf6df48b22faae> <--head> <6030bdbe77a3cd5dbcaeaa3bfd2d7bc3a5b4d3ca> <--schema> <docs/schemas/secure-replay-evidence-v2.schema.json>",
                "cargo <test> <-p> <gocode-daemon> <--test> <desktop_replay_resume_e2e> <--locked>",
            ],
        )
        self.assertNotIn("<HEAD>", "\n".join(self.commands()))
        self.assert_safe_output(result)

    def test_frontend_mode_dispatches_typescript_e2e_architecture_and_docs(self) -> None:
        result = self.run_verifier("frontend")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.commands(),
            [
                "pnpm <--filter> <@gocode/desktop> <test>",
                "pnpm <typecheck>",
                "pnpm <exec> <playwright> <test> <tests/desktop/e2e/replay-resume.spec.ts>",
                "python3 <scripts/desktop/validate_architecture.py>",
                "pnpm <validate:docs>",
            ],
        )
        self.assert_safe_output(result)

    def test_all_mode_dispatches_both_modes_then_diff_check(self) -> None:
        result = self.run_verifier("all")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.commands(),
            [
                "cargo <run> <-p> <gocode-runtime> <--bin> <generate-ui-contract> <--locked> <--> <--check>",
                "python3 <scripts/verify_secure_replay_evidence.py> <--manifest> <docs/evidence/secure-replay-desktop-resume-v1.json> <--legacy-blob> <4713d84e94f68ae9c29de71325d4ecbd8d3096bb>",
                "python3 <scripts/verify_secure_replay_evidence.py> <--manifest> <docs/evidence/secure-replay-desktop-resume-v2.json> <--base> <d4dbabff8272118d99e6388dfbbf6df48b22faae> <--head> <6030bdbe77a3cd5dbcaeaa3bfd2d7bc3a5b4d3ca> <--schema> <docs/schemas/secure-replay-evidence-v2.schema.json>",
                "cargo <test> <-p> <gocode-daemon> <--test> <desktop_replay_resume_e2e> <--locked>",
                "pnpm <--filter> <@gocode/desktop> <test>",
                "pnpm <typecheck>",
                "pnpm <exec> <playwright> <test> <tests/desktop/e2e/replay-resume.spec.ts>",
                "python3 <scripts/desktop/validate_architecture.py>",
                "pnpm <validate:docs>",
                "git <diff> <--check>",
            ],
        )
        self.assert_safe_output(result)

    def test_failing_child_gate_is_propagated_without_later_dispatch(self) -> None:
        result = self.run_verifier("all", fail_command="cargo")

        self.assertEqual(result.returncode, 73)
        self.assertEqual(
            self.commands(),
            [
                "cargo <run> <-p> <gocode-runtime> <--bin> <generate-ui-contract> <--locked> <--> <--check>",
            ],
        )
        self.assert_safe_output(result)


if __name__ == "__main__":
    unittest.main()
