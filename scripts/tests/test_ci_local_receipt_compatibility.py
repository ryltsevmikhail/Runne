from __future__ import annotations

import builtins
import unittest
from unittest import mock

from scripts import ci_local_receipt


class LocalInputReceiptCompatibilityTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
