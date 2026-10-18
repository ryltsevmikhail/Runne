"""Offline and final-validation enforcement for scripts/ci.sh selection.

Covers the two hardening layers around the PATH-first selection:
- rustup network auto-install must be impossible for EVERY command the
  script probes or runs: scripts/ci.sh exports RUSTUP_AUTO_INSTALL=0 (the
  opt-out documented in-binary by the installed rustup >= 1.29), so proxy
  rustc/cargo shims and `rustup which` refuse instead of fetching, even
  when a rust-toolchain.toml pins a missing toolchain.
- After selection, the EFFECTIVE compiler cargo will use ($RUSTC when set,
  else the PATH rustc) and the selected cargo must both report exactly the
  expected version; a wrong explicit RUSTC override or a mismatched cargo
  fails closed with an actionable error instead of silently compiling with
  an unbound toolchain.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.tests import ci_toolchain_test_support as support


MISSING_FILE = '[toolchain]\nchannel = "1.99.9-nightly"\n'
WRONG_RUSTC = "rustc 1.96.0 (old 2025-01-01)"
WRONG_CARGO = "cargo 1.96.0 (old 2025-01-01)"


class CiToolchainOfflineTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        if sys.platform == "darwin":
            self.skipTest("scripts/ci.sh executes the absolute-path macOS "
                          "keychain contract; enforcement covered on Linux")

    def test_proxy_probes_never_auto_install_missing_toolchain_file(self) -> None:
        mode, expected, _, _ = support.PINNED
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            bin_dir, calls = support._mock_bin(
                base, None, None,
                proxy_line=f"rustc 1.99.9-nightly (x 2026-01-01)")
            rustup_calls = support._rustup_bin(
                base, bin_dir, "no installed toolchains", "")
            completed, scratch = support._run_ci(
                base, bin_dir, mode, toolchain_file=MISSING_FILE)
            self.assertEqual(completed.returncode, 1)
            self.assertIn(f"ERROR: rustup is present but toolchain"
                          f" {expected} is not installed", completed.stdout)
            self.assertEqual(list(scratch.iterdir()), [],
                             "proxy or rustup fetched despite RUSTUP_AUTO_INSTALL=0")
            recorded = support._lines(calls)
            self.assertTrue(any(line.startswith(f"{bin_dir}/rustc --version")
                                for line in recorded))
            self.assertTrue(any(line.startswith(f"{bin_dir}/cargo --version")
                                for line in recorded))
            self.assertEqual(support._lines(rustup_calls),
                             [f"{bin_dir}/rustup toolchain list"])
            self.assertNotIn("PASSED", completed.stdout)

    def test_missing_toolchain_fails_closed_without_download(self) -> None:
        mode, expected, _, cargo_line = support.PINNED
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            bin_dir, _ = support._mock_bin(base, WRONG_RUSTC, cargo_line)
            rustup_calls = support._rustup_bin(
                base, bin_dir, "no installed toolchains", "")
            completed, scratch = support._run_ci(base, bin_dir, mode)
            self.assertEqual(completed.returncode, 1)
            self.assertIn(f"ERROR: rustup is present but toolchain"
                          f" {expected} is not installed", completed.stdout)
            self.assertEqual(support._lines(rustup_calls),
                             [f"{bin_dir}/rustup toolchain list"])
            self.assertEqual(list(scratch.iterdir()), [])
            self.assertNotIn("PASSED", completed.stdout)

    def test_wrong_rustc_override_fails_final_validation(self) -> None:
        mode, expected, rustc_line, cargo_line = support.PINNED
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            bin_dir, calls = support._mock_bin(base, rustc_line, cargo_line)
            support._executable(
                bin_dir / "rustc-mismatch", support._tool_mock(WRONG_RUSTC, calls))
            resolved = support._fallback_tools(
                base, calls, rustc_line, cargo_line)
            rustup_calls = support._rustup_bin(
                base, bin_dir, support.LISTING, support.TOOLCHAIN, resolved)
            completed, scratch = support._run_ci(
                base, bin_dir, mode, rustc_env=os.fspath(bin_dir / "rustc-mismatch"))
            self.assertEqual(completed.returncode, 1)
            self.assertIn(f"ERROR: Expected rustc {expected}, got 1.96.0"
                          f" (effective: {bin_dir}/rustc-mismatch)",
                          completed.stdout)
            self.assertEqual(support._lines(rustup_calls), [
                f"{bin_dir}/rustup toolchain list",
                f"{bin_dir}/rustup which --toolchain {support.TOOLCHAIN} cargo",
            ])
            self.assertEqual(list(scratch.iterdir()), [])
            recorded = support._lines(calls)
            self.assertFalse(any("cargo check --workspace" in line
                                 for line in recorded))
            self.assertNotIn("PASSED", completed.stdout)

    def test_mismatched_selected_cargo_fails_final_validation(self) -> None:
        mode, expected, rustc_line, _ = support.PINNED
        for name, mock_rustc in (("fallback", WRONG_RUSTC), ("path", rustc_line)):
            with self.subTest(cargo=name), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                bin_dir, calls = support._mock_bin(base, mock_rustc, None)
                if name == "fallback":
                    resolved = support._fallback_tools(
                        base, calls, rustc_line, WRONG_CARGO)
                    support._rustup_bin(
                        base, bin_dir, support.LISTING, support.TOOLCHAIN, resolved)
                    suffix = ":/usr/bin:/bin"
                else:
                    support._executable(bin_dir / "cargo",
                                        support._tool_mock(WRONG_CARGO, calls))
                    suffix = f":{support._system_bin(base)}"
                completed, _ = support._run_ci(
                    base, bin_dir, mode, path_suffix=suffix)
                self.assertEqual(completed.returncode, 1)
                self.assertIn(f"ERROR: Expected cargo {expected}, got 1.96.0",
                              completed.stdout)
                self.assertIn("Run: rustup run", completed.stdout)
                self.assertNotIn("PASSED", completed.stdout)

    def test_missing_cargo_fails_actionably(self) -> None:
        mode, expected, rustc_line, _ = support.PINNED
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            bin_dir, _ = support._mock_bin(base, rustc_line, None)
            suffix = f":{support._system_bin(base)}"
            completed, _ = support._run_ci(base, bin_dir, mode, path_suffix=suffix)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("ERROR: cargo not found", completed.stdout)

    def test_matching_override_selects_override_compiler_for_cargo(self) -> None:
        mode, expected, rustc_line, cargo_line = support.PINNED
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            compiler_log = base / "compiler-choice.log"
            bin_dir, calls = support._mock_bin(
                base, rustc_line, cargo_line, compiler_log=compiler_log)
            override = bin_dir / "rustc-override"
            support._executable(
                override, support._tool_mock(rustc_line, calls))
            completed, _ = support._run_ci(
                base, bin_dir, mode, rustc_env=os.fspath(override))
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertEqual(set(support._lines(compiler_log)),
                             {os.fspath(override)})
            self.assertIn(f"effective RUSTC override: {override}", completed.stdout)


if __name__ == "__main__":
    unittest.main()
