"""Strict final-inventory libtest transcript regressions."""

import hashlib
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = ROOT / "scripts" / "rc0_candidate" / "verify_rust_inventory.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("strict_inventory_verifier", VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = load_verifier()


def record(listing: bytes) -> dict:
    return {
        "id": "sqlite.managed-connection",
        "stage": "SOURCE_CANDIDATE",
        "package": "runne-store",
        "integration_target": "connection_profile",
        "selector_status": "RESOLVED",
        "fully_qualified_test_name": "sqlite_managed_connection",
        "list_digest": hashlib.sha256(listing).hexdigest(),
        "toolchain": "rustc 1.95.0 (abcdef123 2026-01-02)",
    }


VALID_LIST = b"sqlite_managed_connection: test\n\n1 test, 0 benchmarks\n"
VALID_RUN = (
    b"running 1 test\n"
    b"test sqlite_managed_connection ... ok\n"
    b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
    b"0 filtered out; finished in 0.00s\n"
)


class StrictFinalInventoryTests(unittest.TestCase):
    def test_direct_entry_bootstraps_repository_imports(self):
        inventory = ROOT / "scripts/rc0_candidate/inventories/source-candidate-v1.json"
        result = subprocess.run(
            [sys.executable, str(VERIFIER_PATH), "--inventory", str(inventory),
             "--id", "scanner.withheld-tail"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "PASS: Rust inventory evidence verified\n")
        self.assertEqual(result.stderr, "")

    def verify_with(self, listing: bytes, run: bytes):
        def command(args: tuple[str, ...]):
            if args == ("rustc", "-V"):
                return "rustc 1.95.0 (abcdef123 2026-01-02)\n"
            if args[-1] == "--list":
                if b"\xff" in listing:
                    return listing
                return listing.decode("utf-8")
            return run.decode("utf-8")

        try:
            VERIFIER.verify_record(record(listing), command)
        except VERIFIER.InventoryError:
            raise
        except Exception as error:
            raise AssertionError(
                f"verifier raised {type(error).__name__} instead of InventoryError"
            ) from error

    def test_list_rejects_missing_wrong_duplicate_and_noisy_summaries(self):
        invalid = (
            b"sqlite_managed_connection: test\n",
            b"sqlite_managed_connection: test\n99 tests, 42 benchmarks\n",
            b"sqlite_managed_connection: test\n1 test, 0 benchmarks\nnoise\n",
            (
                b"sqlite_managed_connection: test\n1 test, 0 benchmarks\n"
                b"1 test, 0 benchmarks\n"
            ),
            b"sqlite_managed_connection: test\n\xff\n1 test, 0 benchmarks\n",
        )
        for listing in invalid:
            with self.subTest(listing=listing), self.assertRaisesRegex(
                VERIFIER.InventoryError, "selector|UTF-8|list"
            ):
                self.verify_with(listing, VALID_RUN)

    def test_run_rejects_missing_duplicate_malformed_and_noise_lines(self):
        invalid = (
            VALID_RUN.replace(b"running 1 test\n", b""),
            VALID_RUN.replace(b"running 1 test\n", b"running 1 test\nrunning 1 test\n"),
            VALID_RUN.replace(
                b"test sqlite_managed_connection ... ok\n",
                b"test sqlite_managed_connection ... ok\ntest sqlite_managed_connection ... ok\n",
            ),
            VALID_RUN
            + (
                b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                b"0 filtered out; finished in 0.00s\n"
            ),
            VALID_RUN.replace(b"sqlite_managed_connection", b"other_test"),
            VALID_RUN + b"noise\n",
            VALID_RUN.replace(b"1 passed", b"99 passed"),
        )
        for run in invalid:
            with self.subTest(run=run), self.assertRaisesRegex(
                VERIFIER.InventoryError, "exact run|libtest"
            ):
                self.verify_with(VALID_LIST, run)

    def test_valid_exact_transcript_is_accepted_as_bytes(self):
        self.verify_with(VALID_LIST, VALID_RUN)


if __name__ == "__main__":
    unittest.main()
