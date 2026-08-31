import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.native_package_commands import command


class NativePackageCommandTests(unittest.TestCase):
    def test_macos_secure_store_preserves_owner_home_for_keychain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner_home = root / "owner-home"
            macos = root / "Runne.app" / "Contents" / "MacOS"
            owner_home.mkdir()
            macos.mkdir(parents=True)
            main = macos / "runne-desktop"
            daemon = macos / "runned"
            main.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$HOME\" >> \"$NATIVE_PROBE_INSTALL_ROOT/home-observed\"\n"
                "profile=\"$HOME/Library/Application Support/com.runne.desktop\"\n"
                "mkdir -p \"$profile\"\n"
                ": > \"$profile/profile.sqlite3\"\n"
                "\"$NATIVE_PROBE_INSTALL_ROOT/Runne.app/Contents/MacOS/runned\" &\n"
                "daemon_pid=$!\n"
                "trap 'kill \"$daemon_pid\" 2>/dev/null || true; exit 0' TERM INT\n"
                "wait \"$daemon_pid\"\n",
                encoding="utf-8",
            )
            daemon.write_text(
                "#!/bin/sh\nwhile :; do sleep 1; done\n",
                encoding="utf-8",
            )
            main.chmod(0o755)
            daemon.chmod(0o755)
            environment = {
                **os.environ,
                "HOME": str(owner_home),
                "NATIVE_PROBE_INSTALL_ROOT": str(root),
            }

            result = subprocess.run(
                command(
                    "macos-13-arm64",
                    "secure-store-writer-reader",
                    "Runne.app",
                    "runne-desktop",
                ),
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (root / "home-observed").read_text(encoding="utf-8").splitlines(),
                [str(owner_home), str(owner_home)],
            )


if __name__ == "__main__":
    unittest.main()
