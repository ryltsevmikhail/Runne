"""Contract tests for the mutable RC0 Rust reservation inventory."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts/rc0_candidate/verify_rust_inventory.py"
RUST_RESERVATIONS = (
    ("sqlite.managed-connection", "gocode-store", "connection_profile"),
    ("sqlite.local-reliability", "gocode-store", "local_reliability_inventory"),
    ("phase3.evidence-fixtures", "gocode-store", "evidence_phase3"),
    ("phase3.evidence-shadow-import", "gocode-store", "evidence_phase3"),
    ("phase3.evidence-lineage", "gocode-store", "evidence_phase3"),
    ("phase3.evidence-rollback", "gocode-store", "evidence_phase3"),
    ("phase3.migration-control", "gocode-application", "migration_control"),
    ("phase3.migration-rollout", "gocode-application", "migration_rollout"),
    ("phase3.migration-sqlite", "gocode-store", "migration_sqlite"),
    ("phase3.migration-routing-sqlite", "gocode-store", "migration_routing_sqlite"),
    ("phase3.migration-routing", "gocode-runtime", "migration_routing"),
    ("scanner.withheld-tail", "gocode-runtime", "provider_redaction_recovery"),
    ("scanner.recovery-dispatch", "gocode-store", "provider_dispatch_recovery"),
    ("credentials.native-store", "gocode-secure-store", "provider_credential"),
    ("credentials.lifecycle", "gocode-store", "provider_credential_lifecycle"),
    ("bootstrap.encoder", "gocode-pairing-crypto", "bootstrap_v3"),
    ("bootstrap.persistence", "gocode-store", "bootstrap_reservation_store"),
    ("bootstrap.composition", "gocode-daemon", "bootstrap_reservation_composition"),
    ("bootstrap.http-wire", "gocode-http", "local_session_bootstrap_v3"),
    ("bootstrap.client-wire", "gocode-runtime-client", "local_profile"),
    ("sandbox.containment", "gocode-security", "process_containment_admission"),
    ("pty.process-contract", "gocode-tools", "process_contract"),
    ("mcp.supervision", "gocode-runtime", "plugin_mcp_supervision"),
)


def load_verifier():
    spec = importlib.util.spec_from_file_location("rc0_inventory", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def resolved(identifier: str, package: str, target: str) -> dict[str, str]:
    selector = identifier.replace(".", "_").replace("-", "_")
    listing = f"{selector}: test\n"
    return {
        "id": identifier,
        "stage": "SOURCE_CANDIDATE",
        "package": package,
        "integration_target": target,
        "selector_status": "RESOLVED",
        "fully_qualified_test_name": selector,
        "list_digest": hashlib.sha256(listing.encode()).hexdigest(),
        "toolchain": "rustc 1.95.0",
    }


def inventory(records: list[dict[str, str]], status: str = "MUTABLE") -> dict:
    return {
        "inventory_version": "source-candidate-v1",
        "inventory_status": status,
        "records": records,
    }


class Rc0CandidateInventoryTests(unittest.TestCase):
    def test_rejects_missing_required_category(self) -> None:
        verifier = load_verifier()
        with self.assertRaisesRegex(verifier.InventoryError, "missing required"):
            verifier.validate_inventory(inventory([]))

    def test_rejects_rust_target_that_is_not_an_integration_test(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "gocode-store", "src/lib.rs")
        with self.assertRaisesRegex(verifier.InventoryError, "integration_target"):
            verifier.validate_record(record)

    def test_rejects_duplicate_ids(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "gocode-store", "connection_profile")
        with self.assertRaisesRegex(verifier.InventoryError, "duplicate id"):
            verifier.validate_inventory(inventory([record, record.copy()]))

    def test_rejects_resolved_record_without_all_evidence_fields(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "gocode-store", "connection_profile")
        del record["toolchain"]
        with self.assertRaisesRegex(verifier.InventoryError, "resolved record"):
            verifier.validate_record(record)

    def test_rejects_path_filter_selector(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "gocode-store", "connection_profile")
        record["fully_qualified_test_name"] = "tests/connection_profile.rs"
        with self.assertRaisesRegex(verifier.InventoryError, "path-filter"):
            verifier.validate_record(record)

    def test_unresolved_record_is_rejected_before_cargo(self) -> None:
        verifier = load_verifier()
        record = {
            "id": "sqlite.managed-connection",
            "stage": "SOURCE_CANDIDATE",
            "package": "gocode-store",
            "integration_target": "connection_profile",
            "selector_status": "UNRESOLVED",
        }
        calls: list[tuple[str, ...]] = []

        def command(args: tuple[str, ...]) -> str:
            calls.append(args)
            raise AssertionError("Cargo must not run")

        with self.assertRaisesRegex(verifier.InventoryError, "UNRESOLVED"):
            verifier.verify_record(record, command)
        self.assertEqual(calls, [])

    def test_rejects_checkout_owned_non_rust_expected_count(self) -> None:
        verifier = load_verifier()
        record = {
            "id": "ci-local",
            "stage": "SOURCE_CANDIDATE",
            "record_kind": "EXTERNAL_POLICY",
            "expected_count": 1,
        }
        with self.assertRaisesRegex(verifier.InventoryError, "non-Rust"):
            verifier.validate_record(record)

    def test_rejects_exact_output_without_one_executed_test(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "gocode-store", "connection_profile")

        def command(args: tuple[str, ...]) -> str:
            if args == ("rustc", "-V"):
                return "rustc 1.95.0\n"
            if args[-1] == "--list":
                return "sqlite_managed_connection: test\n"
            return "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"

        with self.assertRaisesRegex(verifier.InventoryError, "exact run"):
            verifier.verify_record(record, command)

    def test_accepts_standard_libtest_list_summary(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "gocode-store", "connection_profile")
        listing = "sqlite_managed_connection: test\n\n1 test, 0 benchmarks\n"
        record["list_digest"] = hashlib.sha256(listing.encode()).hexdigest()

        def command(args: tuple[str, ...]) -> str:
            if args == ("rustc", "-V"):
                return "rustc 1.95.0\n"
            if args[-1] == "--list":
                return listing
            return "running 1 test\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"

        verifier.verify_record(record, command)

    def test_verify_frozen_all_list_verifies_and_exact_runs_every_rust_record(self) -> None:
        verifier = load_verifier()
        rust_records = [resolved(*reservation) for reservation in RUST_RESERVATIONS]
        records = list(rust_records)
        listings: dict[str, str] = {}
        for target in {record["integration_target"] for record in records}:
            listing = "".join(
                f"{record['fully_qualified_test_name']}: test\n"
                for record in records
                if record["integration_target"] == target
            )
            listings[target] = listing
        for record in records:
            record["list_digest"] = hashlib.sha256(
                listings[record["integration_target"]].encode()
            ).hexdigest()
        records.extend(
            {"id": identifier, "stage": "SOURCE_CANDIDATE", "record_kind": "EXTERNAL_POLICY"}
            for identifier in ("docs.claims", "schema.golden-api", "ci-local")
        )
        document = inventory(records, "FROZEN")
        document["final_inventory_digest"] = "0" * 64
        verifier.RUST_IDS = frozenset({"sqlite.managed-connection"})
        calls: list[tuple[str, ...]] = []

        def command(args: tuple[str, ...]) -> str:
            calls.append(args)
            if args == ("rustc", "-V"):
                return "rustc 1.95.0\n"
            if args[-1] == "--list":
                return listings[args[args.index("--test") + 1]]
            return "running 1 test\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"

        verifier.verify_frozen_all(document, command)
        cargo_calls = [call for call in calls if call[0] == "cargo"]
        self.assertEqual(len(cargo_calls), len(rust_records) * 2)
        for record in rust_records:
            matching = [
                call for call in cargo_calls
                if record["package"] in call and record["integration_target"] in call
            ]
            same_target = sum(
                candidate["integration_target"] == record["integration_target"]
                for candidate in rust_records
            )
            self.assertEqual(sum(call[-1] == "--list" for call in matching), same_target)
            self.assertEqual(
                sum(record["fully_qualified_test_name"] in call and call[-1] == "--exact" for call in matching),
                1,
            )


if __name__ == "__main__":
    unittest.main()
