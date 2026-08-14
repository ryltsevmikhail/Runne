"""Pre-G1 rejection coverage for reconciliation receipt verification."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.rc0_policy.owner_reconciliation_context import _context_provider_from_raw
from scripts.rc0_policy.reconciliation import (
    VerifiedReconciliationReceipt,
    verify_reconciliation_receipt,
)
from scripts.rc0_policy.adjunct_registry import verify_adjunct_trust_registry
from scripts.rc0_policy.external_envelope import verify_signed_envelope
from scripts.tests.rc0_platform_envelope_support import _NOW, _fixture_schema_store, valid_fixture_envelope


NOW = 1_700_000_000


class ReconciliationTests(unittest.TestCase):
    def test_rejects_reachable_fixture_domain_and_direct_construction_guard(self) -> None:
        raw, verifier = valid_fixture_envelope()
        schemas = _fixture_schema_store()
        registry = verify_adjunct_trust_registry(
            verify_signed_envelope(raw, schemas, verifier, _NOW), schemas, "FIXTURE_ONLY", _NOW,
        )
        with self.assertRaises(ValueError) as raised:
            verify_reconciliation_receipt(raw, schemas, verifier, registry, NOW)
        self.assertEqual(raised.exception.code, "RECONCILIATION_PRODUCTION_REQUIRED")
        with self.assertRaises(TypeError):
            VerifiedReconciliationReceipt()

    def test_rejects_wrong_token_factory_call(self) -> None:
        with self.assertRaises(TypeError):
            VerifiedReconciliationReceipt._from_verified(object(), object(), object())
        with self.assertRaises(TypeError):
            VerifiedReconciliationReceipt._from_verified()

    def test_owner_context_executes_hashed_bytes_after_path_changes(self) -> None:
        raw = b"def load_context():\n    return 'hashed-bytes'\n"
        with TemporaryDirectory() as directory:
            path = Path(directory) / "context.py"
            path.write_bytes(raw)
            context_raw = path.read_bytes()
            path.write_text("def load_context():\n    return 'path-bytes'\n", encoding="utf-8")
            self.assertEqual(_context_provider_from_raw(context_raw)(), "hashed-bytes")

    def test_stale_registry_blocks_before_receipt_signature_callback(self) -> None:
        raw, verifier = valid_fixture_envelope()
        schemas = _fixture_schema_store()
        registry = verify_adjunct_trust_registry(
            verify_signed_envelope(raw, schemas, verifier, _NOW), schemas, "FIXTURE_ONLY", _NOW,
        )
        calls = 0

        def counted(*args: object) -> object:
            nonlocal calls
            calls += 1
            return verifier(*args)

        with self.assertRaises(ValueError):
            verify_reconciliation_receipt(raw, schemas, counted, registry, _NOW + 11)
        self.assertEqual(calls, 0)


if __name__ == "__main__":
    unittest.main()
