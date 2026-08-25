"""Release identity and platform-policy tests for the native package probe."""

import unittest

from scripts.desktop.native_package_probe import (
    NON_APPLICABLE_OPERATIONS,
    _command,
    required_native_operations,
)


class NativePackageProbeReleaseConfigTests(unittest.TestCase):
    def test_probe_uses_tauri_main_binary_and_component_verification(self) -> None:
        mac = " ".join(_command("macos-13-arm64", "executable-identity", "Runne.app"))
        mac_signing = " ".join(_command("macos-13-arm64", "signing-notarization", "Runne.app"))
        linux = " ".join(_command("ubuntu-22.04-x86_64", "discover-installed-artifact", "Runne.deb"))
        windows = " ".join(_command("windows-10-22h2-x86_64", "discover-installed-artifact", "Runne.exe"))
        self.assertIn("runne-desktop", mac)
        self.assertIn("runned", mac)
        self.assertIn("runned", mac_signing)
        self.assertNotIn("--deep", mac_signing)
        self.assertIn("runne-desktop", linux)
        self.assertIn("runne-desktop.exe", windows)

    def test_linux_signing_is_explicitly_not_applicable(self) -> None:
        self.assertEqual(NON_APPLICABLE_OPERATIONS["ubuntu-22.04-x86_64"], {"signing-notarization"})
        self.assertNotIn("signing-notarization", required_native_operations("ubuntu-22.04-x86_64"))

    def test_protected_operations_use_the_installed_desktop_and_owner_boundary(self) -> None:
        for pair in ("macos-13-arm64", "ubuntu-22.04-x86_64"):
            for operation in (
                "protected-launch",
                "protected-relaunch",
                "secure-store-writer-reader",
                "secure-store-third-process-deny",
            ):
                command = " ".join(_command(pair, operation, "Runne.app"))
                with self.subTest(pair=pair, operation=operation):
                    self.assertIn("--bundled-runtime", command)
                    if operation == "secure-store-third-process-deny":
                        self.assertIn("profile.lock", command)
                    self.assertNotIn("PACKAGED_NATIVE_PROBE_SURFACE_NOT_IMPLEMENTED", command)

        windows = " ".join(
            _command("windows-10-22h2-x86_64", "secure-store-third-process-deny", "Runne.exe")
        )
        self.assertIn("Start-ProbeApp", windows)
        self.assertIn("FileShare]::None", windows)


if __name__ == "__main__":
    unittest.main()
