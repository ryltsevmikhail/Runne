"""Regression tests for PATH-first toolchain selection in scripts/ci.sh.

On a host with /usr/bin/rustup, the receipt namespace's empty scratch
RUSTUP_HOME made `rustup which` auto-install the toolchain over the network
(rustup >= 1.29 auto-installs even for `which`; CARGO_NET_OFFLINE does not
cover rustup), so exact namespace cleanup refused and no receipt could be
published. scripts/ci.sh must accept the exact expected rustc/cargo pair
resolved through PATH without consulting rustup, and its rustup fallback
must resolve ONLY the exact name of an already-installed toolchain from a
successful listing: a failing listing is untrusted, ambiguous, foreign or
custom candidates fail closed, and resolution can never download.
Offline/no-auto-install enforcement and final effective-pair validation are
covered by scripts/tests/test_ci_toolchain_offline.py.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.ci_local_receipt_state import run_local_input_gates
from scripts.tests import ci_toolchain_test_support as support
from scripts.tests import test_ci_local_receipt_security as security_tests


class CiToolchainSelectionTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        if sys.platform == "darwin":
            self.skipTest("scripts/ci.sh executes the absolute-path macOS "
                          "keychain contract; selection covered on Linux")

    def test_expected_path_pair_never_consults_rustup(self) -> None:
        for mode, expected, rustc_line, cargo_line in (support.PINNED, support.MSRV):
            for override in ("unset", "matching"):
                with self.subTest(mode=mode, rustc_override=override), \
                        tempfile.TemporaryDirectory() as location:
                    base = Path(location)
                    compiler_log = base / "compiler-choice.log"
                    bin_dir, calls = support._mock_bin(
                        base, rustc_line, cargo_line,
                        compiler_log=compiler_log)
                    support._rustup_bin(base, bin_dir, "no installed toolchains", "")
                    rustc_env = (os.fspath(bin_dir / "rustc")
                                 if override == "matching" else None)
                    completed, scratch = support._run_ci(
                        base, bin_dir, mode, rustc_env)
                    self.assertEqual(completed.returncode, 0, completed.stdout)
                    self.assertIn(f"=== CI {mode}: PASSED ===", completed.stdout)
                    self.assertFalse((base / "rustup-calls.log").exists())
                    self.assertEqual(list(scratch.iterdir()), [])
                    self.assertIn(f"selected rustc: {bin_dir}/rustc\n"
                                  f"selected cargo: {bin_dir}/cargo",
                                  completed.stdout)
                    recorded = support._lines(calls)
                    self.assertTrue(any(line.startswith(
                        f"{bin_dir}/cargo check --workspace") for line in recorded))
                    self.assertIn(
                        f"{bin_dir}/bash scripts/local-engine/ci.sh {mode}", recorded)
                    self.assertEqual(set(support._lines(compiler_log)),
                                     {f"{bin_dir}/rustc"})

    def test_fallback_resolves_exact_installed_toolchain_name(self) -> None:
        mode, expected, rustc_line, cargo_line = support.PINNED
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            compiler_log = base / "compiler-choice.log"
            bin_dir, calls = support._mock_bin(
                base, "rustc 1.96.0 (old 2025-01-01)", cargo_line,
                compiler_log=compiler_log)
            resolved = support._fallback_tools(
                base, calls, rustc_line, cargo_line, compiler_log=compiler_log)
            rustup_calls = support._rustup_bin(
                base, bin_dir, support.LISTING, support.TOOLCHAIN, resolved)
            completed, scratch = support._run_ci(base, bin_dir, mode)
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn(f"=== CI {mode}: PASSED ===", completed.stdout)
            self.assertEqual(support._lines(rustup_calls), [
                f"{bin_dir}/rustup toolchain list",
                f"{bin_dir}/rustup which --toolchain {support.TOOLCHAIN} cargo",
            ])
            self.assertEqual(list(scratch.iterdir()), [])
            selected = Path(f"{base}/toolchain-root/toolchains/"
                            f"{support.TOOLCHAIN}/bin")
            self.assertIn(f"selected rustc: {selected}/rustc\n"
                          f"selected cargo: {selected}/cargo", completed.stdout)
            recorded = support._lines(calls)
            self.assertTrue(any(line.startswith(
                f"{selected}/cargo check --workspace") for line in recorded))
            self.assertTrue(any(line.startswith(f"{selected}/rustc -vV")
                                for line in recorded))
            self.assertEqual(set(support._lines(compiler_log)),
                             {f"{selected}/rustc"})

    def test_foreign_host_toolchain_resolves_locally_without_download(self) -> None:
        mode, expected, rustc_line, cargo_line = support.PINNED
        foreign = "1.97.1-x86_64-unknown-linux-musl"
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            bin_dir, calls = support._mock_bin(
                base, "rustc 1.96.0 (old 2025-01-01)", cargo_line)
            resolved = support._fallback_tools(
                base, calls, rustc_line, cargo_line, name=foreign)
            rustup_calls = support._rustup_bin(
                base, bin_dir, f"{foreign} (default)", foreign, resolved)
            completed, scratch = support._run_ci(base, bin_dir, mode)
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertEqual(support._lines(rustup_calls), [
                f"{bin_dir}/rustup toolchain list",
                f"{bin_dir}/rustup which --toolchain {foreign} cargo",
            ])
            self.assertEqual(list(scratch.iterdir()), [])
            self.assertIn(
                f"selected cargo: {base}/toolchain-root/toolchains/{foreign}"
                f"/bin/cargo", completed.stdout)

    def _assert_not_installed_failure(self, base: Path, bin_dir: Path,
                                      completed: subprocess.CompletedProcess,
                                      scratch: Path, rustup_calls: Path) -> None:
        expected = support.PINNED[1]
        self.assertEqual(completed.returncode, 1)
        self.assertIn(f"ERROR: rustup is present but toolchain"
                      f" {expected} is not installed", completed.stdout)
        self.assertIn(f"Run: rustup toolchain install {expected}"
                      " --profile minimal", completed.stdout)
        self.assertEqual(support._lines(rustup_calls),
                         [f"{bin_dir}/rustup toolchain list"])
        self.assertEqual(list(scratch.iterdir()), [])
        self.assertNotIn("PASSED", completed.stdout)

    def test_ambiguous_candidates_fail_closed_before_which(self) -> None:
        mode, expected, rustc_line, cargo_line = support.PINNED
        listing = ("1.97.1-aarch64-apple-darwin\n"
                   "1.97.1-x86_64-unknown-linux-gnu")
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            bin_dir, _ = support._mock_bin(
                base, "rustc 1.96.0 (old 2025-01-01)", cargo_line)
            rustup_calls = support._rustup_bin(
                base, bin_dir, listing, support.TOOLCHAIN)
            completed, scratch = support._run_ci(base, bin_dir, mode)
            self._assert_not_installed_failure(
                base, bin_dir, completed, scratch, rustup_calls)

    def test_failing_listing_is_never_trusted(self) -> None:
        mode, expected, rustc_line, cargo_line = support.PINNED
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            bin_dir, _ = support._mock_bin(
                base, "rustc 1.96.0 (old 2025-01-01)", cargo_line)
            rustup_calls = support._rustup_bin(
                base, bin_dir, support.LISTING, support.TOOLCHAIN, list_rc=3)
            completed, scratch = support._run_ci(base, bin_dir, mode)
            self._assert_not_installed_failure(
                base, bin_dir, completed, scratch, rustup_calls)

    def test_custom_linked_toolchain_name_is_rejected(self) -> None:
        mode, expected, rustc_line, cargo_line = support.PINNED
        custom = "1.97.1-evil"
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            bin_dir, _ = support._mock_bin(
                base, "rustc 1.96.0 (old 2025-01-01)", cargo_line)
            linked = base / "custom-link" / "bin" / "cargo"
            linked.parent.mkdir(parents=True)
            rustup_calls = support._rustup_bin(
                base, bin_dir, f"{custom} (default)", custom, linked)
            completed, scratch = support._run_ci(base, bin_dir, mode)
            self.assertEqual(completed.returncode, 1)
            self.assertIn(f"ERROR: rustup is present but toolchain"
                          f" {expected} is not installed", completed.stdout)
            self.assertEqual(support._lines(rustup_calls), [
                f"{bin_dir}/rustup toolchain list",
                f"{bin_dir}/rustup which --toolchain {custom} cargo",
            ])
            self.assertEqual(list(scratch.iterdir()), [])
            self.assertNotIn("PASSED", completed.stdout)

    def test_version_compare_is_exact_without_rustup(self) -> None:
        mode, expected, _, cargo_line = support.PINNED
        cases = (
            ("1.97.10", ("rustc 1.97.10 (x 2026-01-01)", cargo_line),
             f"ERROR: Expected rustc {expected}, got 1.97.10"),
            ("1.97.1-nightly", ("rustc 1.97.1-nightly (x 2026-01-01)", cargo_line),
             f"ERROR: Expected rustc {expected}, got 1.97.1-nightly"),
            ("absent", (None, None), "ERROR: rustc not found"),
        )
        for name, (mock_rustc, mock_cargo), message in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                bin_dir, _ = support._mock_bin(base, mock_rustc, mock_cargo)
                suffix = f":{support._system_bin(base)}"
                completed, _ = support._run_ci(
                    base, bin_dir, mode, path_suffix=suffix)
                self.assertEqual(completed.returncode, 1)
                self.assertIn(message, completed.stdout)

    def test_receipt_namespace_with_rustup_on_path_publishes_receipt(self) -> None:
        for mode, expected, rustc_line, cargo_line in (support.PINNED, support.MSRV):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                bin_dir, _ = support._mock_bin(base, rustc_line, cargo_line)
                support._rustup_bin(base, bin_dir, "no installed toolchains", "")
                repository = base / "repository"
                script = (
                    "#!/bin/sh\n"
                    "set -eu\n"
                    f"export PATH={support._q(bin_dir)}:\"$PATH\"\n"
                    f"export RUSTC={support._q(bin_dir / 'rustc')}\n"
                    f"cd {support._q(repository)}\n"
                    f"\"$RUNNE_TRUSTED_BASH\" scripts/ci.sh {mode}"
                    f" > {support._q(base / 'ci-out.txt')} 2>&1\n"
                )
                security_tests.LocalInputReceiptSecurityTests._repository(
                    repository, script=script)
                (repository / ".gitignore").write_text(
                    "target/\napps/desktop/src-tauri/binaries/\n", encoding="utf-8")
                support._stage_ci_fixture(
                    repository / "scripts", repository / "apps/desktop/dist")
                for arguments in (("add", "."), ("commit", "--quiet", "-m", "ci")):
                    subprocess.run(
                        ("git", "-C", os.fspath(repository), *arguments), check=True)
                receipt = security_tests.LocalInputReceiptSecurityTests._receipt_path(
                    base / "receipt")
                run_local_input_gates(repository, receipt)
                self.assertTrue(receipt.exists())
                self.assertFalse((base / "rustup-calls.log").exists())
                self.assertIn(f"=== CI {mode}: PASSED ===",
                              (base / "ci-out.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
