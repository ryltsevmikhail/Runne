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
            self._write_executable(
                bin_dir / "runned",
                """
                #!/usr/bin/env bash
                set -euo pipefail
                [[ "${1:-}" == doctor ]] || exit 93
                echo "active provider: deepseek_responses_text_v1"
                echo "credential deepseek: configured"
                echo "profile: runne-deepseek-responses-text/1"
                echo "model: deepseek-v4-flash (revision DeepSeek-V4-Flash-0731)"
                """,
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

        self.assertEqual(result.returncode, 91, result.stdout + result.stderr)
        self.assertNotIn("credential is not configured", result.stderr)
        self.assertIn("--- deepseek credential status ---", result.stderr)

    @staticmethod
    def _write_executable(path: pathlib.Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
