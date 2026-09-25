import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).parents[2]
SMOKE = ROOT / "scripts/live-smoke-deepseek.sh"


class LiveSmokeDeepSeekTests(unittest.TestCase):
    def test_label_is_not_captured_as_credential_status(self) -> None:
        result = self._run_smoke_with_profile("gocode-deepseek-responses-text/1")

        self.assertEqual(result.returncode, 91, result.stdout + result.stderr)
        self.assertNotIn("credential is not configured", result.stderr)
        self.assertIn("--- deepseek credential status ---", result.stderr)

    def test_stale_runne_profile_identity_is_refused(self) -> None:
        result = self._run_smoke_with_profile("runne-deepseek-responses-text/1")

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn(
            "refusing: daemon does not expose the exact D1.2 profile/model.",
            result.stderr,
        )

    def _run_smoke_with_profile(self, profile_id: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            bin_dir = pathlib.Path(temporary_directory)
            self._write_executable(
                bin_dir / "runne",
                """
                #!/usr/bin/env bash
                set -euo pipefail
                case "$*" in
                  "provider credential status --provider deepseek") echo configured ;;
                  health) echo healthy ;;
                  status) echo running ;;
                  "conversation create"*) exit 91 ;;
                  *) exit 92 ;;
                esac
                """,
            )
            daemon = """
                #!/usr/bin/env bash
                set -euo pipefail
                [[ "${1:-}" == doctor ]] || exit 93
                echo "active provider: deepseek_responses_text_v1"
                echo "credential deepseek: configured"
                echo "profile: PROFILE_ID"
                echo "model: deepseek-flash (revision 2026-09-21)"
                """.replace("PROFILE_ID", profile_id)
            self._write_executable(
                bin_dir / "runned",
                daemon,
            )
            environment = os.environ.copy()
            environment["RUNNE_LIVE_SMOKE"] = "1"
            result = subprocess.run(
                [str(SMOKE), "--bin-dir", str(bin_dir), "--no-daemon"],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

        return result

    @staticmethod
    def _write_executable(path: pathlib.Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
