from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/macos-ci-keychain.sh"


@unittest.skipUnless(platform.system() == "Darwin", "macOS Keychain test")
class MacOsCiKeychainTests(unittest.TestCase):
    def test_isolated_keychain_is_unlocked_and_exactly_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            scratch = root / "tmp"
            home.mkdir(mode=0o700)
            scratch.mkdir(mode=0o700)
            # Cleanup runs from the ci.sh EXIT trap under `set -euo pipefail`;
            # exercising that exact path guards against a non-zero cleanup
            # return overriding a successful script exit (cube PASSED + failed).
            script = """
set -euo pipefail
source "$1"
trap runne_ci_macos_keychain_cleanup EXIT
runne_ci_macos_keychain_setup
/usr/bin/security show-keychain-info "$RUNNE_CI_MACOS_KEYCHAIN"
/usr/bin/security add-generic-password -a fixture -s runne-ci-fixture \
  -w fixture-value "$RUNNE_CI_MACOS_KEYCHAIN" >/dev/null
echo "=== CI fixture: PASSED ==="
"""
            environment = {
                "HOME": os.fspath(home),
                "TMPDIR": os.fspath(scratch),
                "PATH": "/usr/bin:/bin",
            }
            result = subprocess.run(
                ("/bin/bash", "-c", script, "bash", os.fspath(HELPER)),
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no-timeout", result.stdout + result.stderr)
            self.assertIn("PASSED", result.stdout)
            self.assertEqual(list(home.iterdir()), [])
            self.assertEqual(list(scratch.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
