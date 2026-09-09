"""Host-version admission tests for native package qualification."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts.desktop import native_package_probe


class NativePackageProbeHostVersionTests(unittest.TestCase):
    def test_macos_14_pair_accepts_newer_macos_release(self) -> None:
        with (
            patch.object(native_package_probe, "current_platform", return_value=("darwin", "arm64")),
            patch.object(native_package_probe, "_host_version", return_value="27.0"),
        ):
            result = native_package_probe.preflight("macos-14-arm64")

        self.assertEqual(result["blocker_code"], "MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED")
        self.assertEqual(result["detail"], "preflight passed; package probe and external provenance required")

    def test_macos_14_pair_rejects_older_macos_release(self) -> None:
        with (
            patch.object(native_package_probe, "current_platform", return_value=("darwin", "arm64")),
            patch.object(native_package_probe, "_host_version", return_value="13.7.6"),
        ):
            result = native_package_probe.preflight("macos-14-arm64")

        self.assertEqual(result["blocker_code"], "RUNNER_TRUST_UNVERIFIED")
        self.assertEqual(result["detail"], "host version does not match required matrix")


if __name__ == "__main__":
    unittest.main()
