from __future__ import annotations

import builtins
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import ci_local_receipt
from scripts.ci_local_receipt_common import LocalInputReceiptError, atomic_write
from scripts.ci_local_receipt_runtime import resolve_trusted_runtime


ROOT = Path(__file__).resolve().parents[2]


class LocalInputReceiptCompatibilityTests(unittest.TestCase):
    def test_unset_tmpdir_fallback_is_canonical_before_receipt_publish(self) -> None:
        source = (ROOT / "scripts/ci-local.sh").read_text(encoding="utf-8")
        canonicalize = 'state_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)"'
        allocate = 'state_directory="$(mktemp -d "$state_root/gocode-ci-local.XXXXXX")"'
        self.assertIn(canonicalize, source)
        self.assertIn(allocate, source)
        self.assertLess(source.index(canonicalize), source.index(allocate))

        with tempfile.TemporaryDirectory(dir="/tmp") as aliased_directory:
            aliased = Path(aliased_directory)
            canonical = aliased.resolve(strict=True)
            if aliased == canonical:
                self.skipTest("platform /tmp has no symlink alias")
            with self.assertRaises(LocalInputReceiptError):
                atomic_write(aliased / "receipt.json", b"{}")
            atomic_write(canonical / "receipt.json", b"{}")
            self.assertEqual((canonical / "receipt.json").read_bytes(), b"{}")

    def test_valid_receipt_shape_supports_zip_without_strict_keyword(self) -> None:
        record = {
            "schema": "gocode.local-input-receipt/1",
            "receipt_nonce": "0" * 64,
            "issued_at_unix": 1,
            "local_inputs": "LOCAL_INPUTS_COMPLETE",
            "source_revision": "0" * 40,
            "source_tree": "1" * 40,
            "repository_identity": {
                "worktree_dev": 1,
                "worktree_ino": 2,
                "git_dir_dev": 3,
                "git_dir_ino": 4,
            },
            "git_metadata_sha256": "2" * 64,
            "input_script_sha256": "3" * 64,
            "inventories": {
                "source_candidate_sha256": "4" * 64,
                "phase3_sha256": "5" * 64,
                "local_reliability_sha256": "6" * 64,
                "taxonomy_migration_sha256": "7" * 64,
                "frozen_inventory_digest": "8" * 64,
            },
            "executables": {},
            "toolchains": {
                "pinned": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
                "msrv": "rustc 1.95.0 (000000000 2026-01-01)",
            },
            "gate_exit_status": 0,
            "gate_results": [
                {"gate": gate, "result": "SATISFIED"}
                for gate in (
                    "local-structural",
                    "runtime-pinned",
                    "runtime-msrv",
                    "frontend",
                    "documentation-architecture",
                )
            ],
        }

        def zip_without_strict(*iterables):
            return builtins.zip(*iterables)

        with mock.patch.object(
            ci_local_receipt, "valid_executable_shape", return_value=True
        ), mock.patch.object(
            ci_local_receipt, "zip", zip_without_strict, create=True
        ):
            try:
                valid = ci_local_receipt._valid_shape(record)
            except TypeError as error:
                self.fail(f"receipt validation requires unsupported zip keyword: {error}")

        self.assertTrue(valid)


class CiToolchainPairCompatibilityTests(unittest.TestCase):
    """The binaries the receipt namespace binds must satisfy scripts/ci.sh.

    scripts/ci.sh accepts a PATH-resolved rustc/cargo pair only when both
    report exactly the lane's expected version, so the lane shims the
    receipt namespace symlinks (the same binaries `resolve_trusted_runtime`
    hashes) must report that exact pair under a clean environment.
    """

    def test_receipt_bound_toolchains_report_exact_lane_versions(self) -> None:
        runtime = resolve_trusted_runtime(ROOT)
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        for lane, version in (("pinned", "1.97.1"), ("msrv", "1.95.0")):
            with self.subTest(lane=lane):
                for tool in ("rustc", "cargo"):
                    completed = subprocess.run(
                        (os.fspath(runtime.rust_commands[lane][tool]), "--version"),
                        env=environment, capture_output=True, text=True, check=True,
                    )
                    self.assertEqual(completed.stdout.split()[1], version)

    def test_ci_sh_source_orders_path_pair_before_rustup(self) -> None:
        ci_sh = (ROOT / "scripts/ci.sh").read_text(encoding="utf-8")
        helper = (ROOT / "scripts/ci-toolchain-select.sh").read_text(
            encoding="utf-8")
        markers = (
            "export RUSTUP_AUTO_INSTALL=0",
            'if [ "$PATH_RUSTC_VER" = "$EXPECTED" ]',
            'TOOLCHAIN_NAME="$(_rustup_exact_toolchain)"',
            'rustup which --toolchain "$TOOLCHAIN_NAME" cargo',
            'if [ "$RUSTC_VER" != "$EXPECTED" ]',
            'if [ "$CARGO_VER" != "$EXPECTED" ]',
        )
        for marker in markers:
            self.assertIn(marker, helper)
        positions = [helper.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("source scripts/ci-toolchain-select.sh", ci_sh)


if __name__ == "__main__":
    unittest.main()
