"""Contract tests for strict Phase 3 libtest evidence parsing."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))
import phase3_inventory as inventory


class Phase3InventoryTests(unittest.TestCase):
    def test_list_rejects_duplicate_benchmark_ignored_and_malformed_utf8(self) -> None:
        fixtures = (
            b"suite::case: test\nsuite::case: test\n\n2 tests, 0 benchmarks\n",
            b"suite::case: benchmark\n\n0 tests, 1 benchmark\n",
            b"suite::case: test ignored\n\n1 test, 0 benchmarks\n",
            b"suite::case: test\n\xff\n",
        )
        for raw in fixtures:
            with self.subTest(raw=raw), self.assertRaises(inventory.Phase3InventoryError):
                inventory.parse_libtest_list(raw)

    def test_list_requires_one_zero_benchmark_summary_matching_entries(self) -> None:
        fixtures = (
            b"suite::case: test\n",
            b"suite::case: test\n\n1 test, 0 benchmarks\n1 test, 0 benchmarks\n",
            b"suite::case: test\n\n99 tests, 0 benchmarks\n",
            b"suite::case: test\n\n1 test, 1 benchmarks\n",
        )
        for raw in fixtures:
            with self.subTest(raw=raw), self.assertRaises(inventory.Phase3InventoryError):
                inventory.parse_libtest_list(raw)

    def test_run_requires_one_executed_one_passed_zero_ignored(self) -> None:
        listing = ("suite::case",)
        valid_run = (
            b"\nrunning 1 test\ntest suite::case ... ok\n\n"
            b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            b"0 filtered out; finished in 0.00s\n"
        )
        self.assertEqual(
            inventory.verify_exact_execution(listing, valid_run),
            inventory.ExactExecution(executed=1, passed=1, ignored=0),
        )
        invalid_run = valid_run.replace(b"0 ignored", b"1 ignored")
        with self.assertRaises(inventory.Phase3InventoryError):
            inventory.verify_exact_execution(listing, invalid_run)


if __name__ == "__main__":
    unittest.main()
