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
    ("sqlite.managed-connection", "runne-store", "connection_profile"),
    ("sqlite.local-reliability", "runne-store", "local_reliability_inventory"),
    ("phase3.evidence-fixtures", "runne-store", "evidence_phase3"),
    ("phase3.evidence-shadow-import", "runne-store", "evidence_phase3"),
    ("phase3.evidence-lineage", "runne-store", "evidence_phase3"),
    ("phase3.evidence-rollback", "runne-store", "evidence_phase3"),
    ("phase3.migration-control", "runne-application", "migration_control"),
    ("phase3.migration-rollout", "runne-application", "migration_rollout"),
    ("phase3.migration-sqlite", "runne-store", "migration_sqlite"),
    ("phase3.migration-routing-sqlite", "runne-store", "migration_routing_sqlite"),
    ("phase3.migration-routing", "runne-runtime", "migration_routing"),
    ("scanner.withheld-tail", "runne-runtime", "provider_redaction_recovery"),
    ("scanner.recovery-dispatch", "runne-store", "provider_dispatch_recovery"),
    ("credentials.native-store", "runne-secure-store", "provider_credential"),
    ("credentials.lifecycle", "runne-store", "provider_credential_lifecycle"),
    ("bootstrap.encoder", "runne-pairing-crypto", "bootstrap_v3"),
    ("bootstrap.persistence", "runne-store", "bootstrap_reservation_store"),
    ("bootstrap.composition", "runne-daemon", "bootstrap_reservation_composition"),
    ("bootstrap.http-wire", "runne-http", "local_session_bootstrap_v3"),
    ("bootstrap.client-wire", "runne-runtime-client", "local_profile"),
    ("sandbox.containment", "runne-security", "process_containment_admission"),
    ("pty.process-contract", "runne-tools", "process_contract"),
    ("mcp.supervision", "runne-runtime", "plugin_mcp_supervision"),
)
def load_verifier():
    spec = importlib.util.spec_from_file_location("rc0_inventory", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module
def resolved(identifier: str, package: str, target: str) -> dict[str, str]:
    selector = identifier.replace(".", "_").replace("-", "_")
    listing = f"{selector}: test\n\n1 test, 0 benchmarks\n"
    return {
        "id": identifier,
        "stage": "SOURCE_CANDIDATE",
        "package": package,
        "integration_target": target,
        "selector_status": "RESOLVED",
        "fully_qualified_test_name": selector,
        "list_digest": hashlib.sha256(listing.encode()).hexdigest(),
        "toolchain": "rustc 1.95.0 (abcdef123 2026-01-02)",
    }
def inventory(records: list[dict[str, str]], status: str = "MUTABLE") -> dict:
    return {
        "inventory_version": "source-candidate-v1",
        "inventory_status": status,
        "records": records,
    }
def frozen_inventory(verifier, records: list[dict[str, str]]) -> dict:
    records = list(records) + [
        {"id": identifier, "stage": "SOURCE_CANDIDATE", "record_kind": "EXTERNAL_POLICY"}
        for identifier in ("docs.claims", "schema.golden-api", "ci-local")
    ]
    document = inventory(records, "FROZEN")
    document["final_inventory_digest"] = verifier.final_inventory_digest(document)
    return document
def resolved_reservations() -> list[dict[str, str]]:
    records = [resolved(*reservation) for reservation in RUST_RESERVATIONS]
    listings = {
        target: "".join(f"{record['fully_qualified_test_name']}: test\n" for record in records
                        if record["integration_target"] == target)
        for target in {record["integration_target"] for record in records}
    }
    listings = {
        target: listing + f"\n{listing.count(': test')} tests, 0 benchmarks\n"
        for target, listing in listings.items()
    }
    for record in records:
        record["list_digest"] = hashlib.sha256(listings[record["integration_target"]].encode()).hexdigest()
    return records
class Rc0CandidateInventoryTests(unittest.TestCase):
    def test_rejects_missing_required_category(self) -> None:
        verifier = load_verifier()
        with self.assertRaisesRegex(verifier.InventoryError, "missing required"):
            verifier.validate_inventory(inventory([]))

    def test_rejects_rust_target_that_is_not_an_integration_test(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "runne-store", "src/lib.rs")
        with self.assertRaisesRegex(verifier.InventoryError, "integration_target"):
            verifier.validate_record(record)

    def test_rejects_duplicate_ids(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "runne-store", "connection_profile")
        with self.assertRaisesRegex(verifier.InventoryError, "duplicate id"):
            verifier.validate_inventory(inventory([record, record.copy()]))

    def test_rejects_resolved_record_without_all_evidence_fields(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "runne-store", "connection_profile")
        del record["toolchain"]
        with self.assertRaisesRegex(verifier.InventoryError, "invalid toolchain"):
            verifier.validate_record(record)

    def test_rejects_path_filter_selector(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "runne-store", "connection_profile")
        record["fully_qualified_test_name"] = "tests/connection_profile.rs"
        with self.assertRaisesRegex(verifier.InventoryError, "path-filter"):
            verifier.validate_record(record)

    def test_rejects_rust_record_not_owned_by_a_reservation(self) -> None:
        verifier = load_verifier()
        with self.assertRaisesRegex(verifier.InventoryError, "not owned"):
            verifier.validate_record(resolved("unowned", "runne-store", "candidate"))

    def test_unresolved_record_is_rejected_before_cargo(self) -> None:
        verifier = load_verifier()
        record = {
            "id": "sqlite.managed-connection",
            "stage": "SOURCE_CANDIDATE",
            "package": "runne-store",
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
        record = resolved("sqlite.managed-connection", "runne-store", "connection_profile")

        def command(args: tuple[str, ...]) -> str:
            if args == ("rustc", "-V"):
                return "rustc 1.95.0 (abcdef123 2026-01-02)\n"
            if args[-1] == "--list":
                return "sqlite_managed_connection: test\n\n1 test, 0 benchmarks\n"
            return "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"

        with self.assertRaisesRegex(verifier.InventoryError, "exact run"):
            verifier.verify_record(record, command)

    def test_accepts_standard_libtest_list_summary(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "runne-store", "connection_profile")
        listing = "sqlite_managed_connection: test\n\n1 test, 0 benchmarks\n"
        record["list_digest"] = hashlib.sha256(listing.encode()).hexdigest()

        def command(args: tuple[str, ...]) -> str:
            if args == ("rustc", "-V"):
                return "rustc 1.95.0 (abcdef123 2026-01-02)\n"
            if args[-1] == "--list":
                return listing
            return (
                "running 1 test\ntest sqlite_managed_connection ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.00s\n"
            )

        verifier.verify_record(record, command)

    def test_frozen_validation_rejects_bad_records_before_cargo(self) -> None:
        verifier = load_verifier()
        for expected, mutate in (
            ("unresolved", lambda records: records[0].update(selector_status="UNRESOLVED")),
            ("duplicate id", lambda records: records.append(records[0].copy())),
            ("missing required", lambda records: records.pop()),
            ("missing required", lambda records: records.append(resolved("extra", "runne-store", "extra"))),
            ("reservation tuple changed", lambda records: records[0].update(package="wrong")),
            ("resolved record", lambda records: records[0].pop("list_digest")),
        ):
            with self.subTest(expected=expected):
                document = frozen_inventory(verifier, resolved_reservations())
                mutate(document["records"])
                calls: list[tuple[str, ...]] = []
                with self.assertRaisesRegex(verifier.InventoryError, expected):
                    verifier.verify_frozen_all(document, lambda args: calls.append(args) or "")
                self.assertEqual(calls, [])

    def test_frozen_rejects_malformed_toolchain_before_commands(self) -> None:
        verifier = load_verifier()
        for value in ("arbitrary", 1, "rustc 1.97.1 (BADc0ffee 2026-07-14)", "rustc 1.97.1 (8bab26f4f 2026-99-14)", None):
            with self.subTest(value=value):
                document = frozen_inventory(verifier, resolved_reservations())
                record = document["records"][0]
                if value is None:
                    record.pop("toolchain")
                else:
                    record["toolchain"] = value
                document["final_inventory_digest"] = verifier.final_inventory_digest(document)
                calls: list[tuple[str, ...]] = []
                with self.assertRaisesRegex(verifier.InventoryError, "invalid toolchain"):
                    verifier.verify_frozen_all(document, lambda args: calls.append(args) or "")
                self.assertEqual(calls, [])

    def test_frozen_digest_is_canonical_and_checked_before_cargo(self) -> None:
        verifier = load_verifier()
        records = resolved_reservations()
        first = frozen_inventory(verifier, records)
        second = frozen_inventory(verifier, list(reversed(records)))
        self.assertEqual(first["final_inventory_digest"], second["final_inventory_digest"])
        first["final_inventory_digest"] = "0" * 64
        calls: list[tuple[str, ...]] = []
        with self.assertRaisesRegex(verifier.InventoryError, "final inventory digest mismatch"):
            verifier.verify_frozen_all(first, lambda args: calls.append(args) or "")
        self.assertEqual(calls, [])

    def test_list_mismatch_refuses_exact_execution(self) -> None:
        verifier = load_verifier()
        record = resolved("sqlite.managed-connection", "runne-store", "connection_profile")
        for listing in ("0 tests, 0 benchmarks\n", "sqlite_managed_connection: test\nsqlite_managed_connection: test\n"):
            with self.subTest(listing=listing):
                calls: list[tuple[str, ...]] = []
                with self.assertRaisesRegex(verifier.InventoryError, "libtest list"):
                    verifier.verify_record(record, lambda args: calls.append(args) or listing)
                self.assertEqual(len(calls), 1)
        record["list_digest"] = "0" * 64
        with self.assertRaisesRegex(verifier.InventoryError, "list digest changed"):
            verifier.verify_record(
                record,
                lambda args: "sqlite_managed_connection: test\n\n1 test, 0 benchmarks\n",
            )

    def test_verify_frozen_all_list_verifies_and_exact_runs_every_rust_record(self) -> None:
        verifier = load_verifier()
        rust_records = resolved_reservations()
        records = list(rust_records)
        listings: dict[str, str] = {}
        for target in {record["integration_target"] for record in records}:
            listing = "".join(
                f"{record['fully_qualified_test_name']}: test\n"
                for record in records
                if record["integration_target"] == target
            )
            listing += f"\n{listing.count(': test')} tests, 0 benchmarks\n"
            listings[target] = listing
        for record in records:
            record["list_digest"] = hashlib.sha256(
                listings[record["integration_target"]].encode()
            ).hexdigest()
        document = frozen_inventory(verifier, records)
        verifier.RUST_IDS = frozenset({"sqlite.managed-connection"})
        calls: list[tuple[str, ...]] = []

        def command(args: tuple[str, ...]) -> str:
            calls.append(args)
            if args == ("rustc", "-V"):
                return "rustc 1.95.0 (abcdef123 2026-01-02)\n"
            if args[-1] == "--list":
                return listings[args[args.index("--test") + 1]]
            selector = args[args.index("--") - 1]
            return (
                f"running 1 test\ntest {selector} ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.00s\n"
            )

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
