#!/usr/bin/env python3
"""Fail-closed verifier for the RC0 Rust candidate test reservations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path


RUST_IDS = frozenset({
    "sqlite.managed-connection", "sqlite.local-reliability",
    "phase3.evidence-fixtures", "phase3.evidence-shadow-import",
    "phase3.evidence-lineage", "phase3.evidence-rollback",
    "phase3.migration-control", "phase3.migration-rollout", "phase3.migration-sqlite",
    "phase3.migration-routing-sqlite", "phase3.migration-routing",
    "scanner.withheld-tail", "scanner.recovery-dispatch", "credentials.native-store",
    "credentials.lifecycle", "bootstrap.encoder", "bootstrap.persistence",
    "bootstrap.composition", "bootstrap.http-wire", "bootstrap.client-wire",
    "sandbox.containment", "pty.process-contract", "mcp.supervision",
})
EXTERNAL_IDS = frozenset({"docs.claims", "schema.golden-api", "ci-local"})
REQUIRED_IDS = RUST_IDS | EXTERNAL_IDS
TARGET_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SELECTOR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
LIST_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_:]*): test$")
RESULT_RE = re.compile(r"test result: ok\. 1 passed; 0 failed; 0 ignored;")


class InventoryError(ValueError):
    """An inventory is incomplete, unsafe, or not exact-run evidence."""


Command = Callable[[tuple[str, ...]], str]


def rust_record(record: dict) -> bool:
    return "package" in record or "integration_target" in record


def validate_record(record: dict) -> None:
    if not isinstance(record, dict) or not isinstance(record.get("id"), str):
        raise InventoryError("record requires string id")
    if record.get("stage") != "SOURCE_CANDIDATE":
        raise InventoryError(f"invalid stage for {record['id']}")
    if rust_record(record):
        _validate_rust_record(record)
    elif record.get("record_kind") != "EXTERNAL_POLICY" or set(record) != {"id", "stage", "record_kind"}:
        raise InventoryError(f"non-Rust record {record['id']} contains checkout-owned execution data")


def _validate_rust_record(record: dict) -> None:
    unresolved = {"id", "stage", "package", "integration_target", "selector_status"}
    resolved = unresolved | {"fully_qualified_test_name", "list_digest", "toolchain"}
    status = record.get("selector_status")
    if status == "UNRESOLVED":
        if set(record) != unresolved:
            raise InventoryError(f"unresolved record {record['id']} has evidence fields")
    elif status == "RESOLVED":
        if set(record) != resolved or not all(record.get(key) for key in resolved - unresolved):
            raise InventoryError(f"resolved record {record['id']} lacks exactly one selector/list digest/toolchain")
    else:
        raise InventoryError(f"record {record['id']} has invalid selector_status")
    if not isinstance(record.get("package"), str) or not TARGET_RE.fullmatch(str(record.get("integration_target"))):
        raise InventoryError(f"record {record['id']} requires a Cargo --test integration_target")
    selector = record.get("fully_qualified_test_name")
    if selector is not None and not SELECTOR_RE.fullmatch(str(selector)):
        raise InventoryError(f"record {record['id']} has a path-filter selector")
    digest = record.get("list_digest")
    if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise InventoryError(f"record {record['id']} has invalid list digest")


def validate_inventory(document: dict) -> None:
    if not isinstance(document, dict) or document.get("inventory_version") != "source-candidate-v1":
        raise InventoryError("invalid inventory version")
    status = document.get("inventory_status")
    if status not in {"MUTABLE", "FROZEN"}:
        raise InventoryError("invalid inventory status")
    if status == "MUTABLE" and set(document) != {"inventory_version", "inventory_status", "records"}:
        raise InventoryError("mutable inventory contains frozen or checkout-owned authority data")
    if status == "FROZEN" and (
        set(document) != {"inventory_version", "inventory_status", "records", "final_inventory_digest"}
        or not re.fullmatch(r"[0-9a-f]{64}", str(document.get("final_inventory_digest")))
    ):
        raise InventoryError("frozen inventory requires canonical final_inventory_digest")
    records = document.get("records")
    if not isinstance(records, list):
        raise InventoryError("inventory requires records")
    ids = [record.get("id") for record in records if isinstance(record, dict)]
    if len(ids) != len(records) or len(set(ids)) != len(ids):
        raise InventoryError("duplicate id in inventory")
    if set(ids) != REQUIRED_IDS:
        raise InventoryError("missing required or unexpected reservation category")
    for record in records:
        validate_record(record)


def subprocess_command(args: tuple[str, ...]) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=True)
    return result.stdout


def _list_command(record: dict) -> tuple[str, ...]:
    return ("cargo", "test", "--locked", "-p", record["package"], "--test", record["integration_target"], "--", "--list")


def _exact_command(record: dict) -> tuple[str, ...]:
    return ("cargo", "test", "--locked", "-p", record["package"], "--test", record["integration_target"], record["fully_qualified_test_name"], "--", "--exact")


def verify_record(record: dict, command: Command = subprocess_command) -> None:
    validate_record(record)
    if record.get("selector_status") != "RESOLVED":
        raise InventoryError(f"record {record['id']} is UNRESOLVED")
    listing = command(_list_command(record))
    listed = [match.group(1) for line in listing.splitlines() if (match := LIST_RE.fullmatch(line))]
    selector = record["fully_qualified_test_name"]
    if listed.count(selector) != 1 or len(listed) != len(listing.splitlines()):
        raise InventoryError(f"record {record['id']} selector is not exactly one listed test")
    if hashlib.sha256(listing.encode()).hexdigest() != record["list_digest"]:
        raise InventoryError(f"record {record['id']} list digest changed")
    if command(("rustc", "-V")).strip() != record["toolchain"]:
        raise InventoryError(f"record {record['id']} toolchain changed")
    output = command(_exact_command(record))
    if "running 1 test" not in output or not RESULT_RE.search(output):
        raise InventoryError(f"record {record['id']} exact run did not execute one passing test")


def verify_frozen_all(document: dict, command: Command = subprocess_command) -> None:
    validate_inventory(document)
    if document["inventory_status"] != "FROZEN":
        raise InventoryError("--verify-frozen-all requires FROZEN inventory")
    records = sorted((record for record in document["records"] if rust_record(record)), key=lambda record: record["id"])
    completed: set[str] = set()
    for record in records:
        verify_record(record, command)
        completed.add(record["id"])
    if completed != RUST_IDS:
        raise InventoryError("frozen-all completed Rust IDs do not equal inventory Rust IDs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--id")
    group.add_argument("--verify-frozen-all", action="store_true")
    args = parser.parse_args()
    try:
        document = json.loads(args.inventory.read_text(encoding="utf-8"))
        validate_inventory(document)
        if args.verify_frozen_all:
            verify_frozen_all(document)
        else:
            record = next((item for item in document["records"] if item["id"] == args.id), None)
            if record is None or not rust_record(record):
                raise InventoryError("unknown Rust reservation id")
            verify_record(record)
    except (InventoryError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}")
        return 1
    print("PASS: Rust inventory evidence verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
