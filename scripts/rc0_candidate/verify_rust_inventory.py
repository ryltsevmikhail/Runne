#!/usr/bin/env python3
"""Fail-closed RC0 verifier; frozen digests hash sorted JSON sans themselves."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Union

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.phase3_inventory import (
    Phase3InventoryError,
    parse_libtest_list,
    verify_exact_execution,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
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
RUST_IDS = frozenset(identifier for identifier, _, _ in RUST_RESERVATIONS)
RUST_TUPLES = {identifier: ("SOURCE_CANDIDATE", package, target)
               for identifier, package, target in RUST_RESERVATIONS}
EXTERNAL_IDS = frozenset({"docs.claims", "schema.golden-api", "ci-local"})
REQUIRED_IDS = RUST_IDS | EXTERNAL_IDS
TARGET_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SELECTOR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
TOOLCHAIN_RE = re.compile(
    r"^rustc (?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*) "
    r"\([0-9a-f]+ ([0-9]{4}-[0-9]{2}-[0-9]{2})\)$"
)


class InventoryError(ValueError):
    """An inventory is incomplete, unsafe, or not exact-run evidence."""


Command = Callable[[tuple[str, ...]], Union[bytes, str]]


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
        if not _valid_toolchain(record.get("toolchain")):
            raise InventoryError(f"record {record['id']} has invalid toolchain")
        if set(record) != resolved or not all(record.get(key) for key in resolved - unresolved):
            raise InventoryError(f"resolved record {record['id']} lacks exactly one selector/list digest/toolchain")
    else:
        raise InventoryError(f"record {record['id']} has invalid selector_status")
    if not isinstance(record.get("package"), str) or not TARGET_RE.fullmatch(str(record.get("integration_target"))):
        raise InventoryError(f"record {record['id']} requires a Cargo --test integration_target")
    if record["id"] not in RUST_TUPLES:
        raise InventoryError(f"record {record['id']} is not owned by a completed source task")
    if RUST_TUPLES[record["id"]] != (
        record["stage"], record["package"], record["integration_target"]
    ):
        raise InventoryError(f"record {record['id']} reservation tuple changed")
    selector = record.get("fully_qualified_test_name")
    if selector is not None and not SELECTOR_RE.fullmatch(str(selector)):
        raise InventoryError(f"record {record['id']} has a path-filter selector")
    digest = record.get("list_digest")
    if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise InventoryError(f"record {record['id']} has invalid list digest")


def _valid_toolchain(toolchain: object) -> bool:
    match = TOOLCHAIN_RE.fullmatch(toolchain) if isinstance(toolchain, str) else None
    if match is None:
        return False
    try:
        date.fromisoformat(match.group(1))
    except ValueError:
        return False
    return True


def canonical_inventory_bytes(document: dict) -> bytes:
    """UTF-8 JSON: sort record IDs and object keys; omit final_inventory_digest."""
    payload = {key: value for key, value in document.items() if key != "final_inventory_digest"}
    payload["records"] = sorted(payload.get("records", []), key=lambda record: record.get("id", ""))
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def final_inventory_digest(document: dict) -> str:
    return hashlib.sha256(canonical_inventory_bytes(document)).hexdigest()


def validate_inventory(document: dict) -> None:
    if not isinstance(document, dict) or document.get("inventory_version") != "source-candidate-v1":
        raise InventoryError("invalid inventory version")
    status = document.get("inventory_status")
    if status not in {"MUTABLE", "FROZEN"}:
        raise InventoryError("invalid inventory status")
    mutable_fields = {"inventory_version", "inventory_status", "records"}
    frozen_fields = mutable_fields | {"final_inventory_digest"}
    if status == "MUTABLE" and set(document) != mutable_fields:
        raise InventoryError("mutable inventory contains checkout-owned authority data")
    if status == "FROZEN" and (
        set(document) != frozen_fields
        or not re.fullmatch(r"[0-9a-f]{64}", str(document.get("final_inventory_digest")))
    ):
        raise InventoryError("frozen inventory requires a lowercase 64-hex final_inventory_digest")
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
    if status == "FROZEN":
        unresolved = next((record["id"] for record in records
                           if rust_record(record) and record["selector_status"] != "RESOLVED"), None)
        if unresolved is not None:
            raise InventoryError(f"frozen inventory contains UNRESOLVED record {unresolved}")
        if document["final_inventory_digest"] != final_inventory_digest(document):
            raise InventoryError("final inventory digest mismatch")


def _cargo_temp_root() -> Path:
    root = REPOSITORY_ROOT / "target"
    root.mkdir(mode=0o700, exist_ok=True)
    metadata = os.lstat(root)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or root.resolve(strict=True).parent != REPOSITORY_ROOT):
        raise InventoryError("Cargo temporary root is not an owned repository directory")
    return root


def subprocess_command(args: tuple[str, ...]) -> bytes:
    if args[0] != "cargo":
        return subprocess.run(args, check=True, capture_output=True).stdout
    with tempfile.TemporaryDirectory(prefix="rc0-inventory-", dir=_cargo_temp_root()) as temporary:
        metadata = os.lstat(temporary)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise InventoryError("Cargo temporary directory is not owner-private")
        environment = {**os.environ, "TMPDIR": temporary}
        result = subprocess.run(args, check=True, capture_output=True, env=environment)
    return result.stdout


def _raw_output(output: bytes | str) -> bytes:
    try:
        return output if isinstance(output, bytes) else output.encode("utf-8")
    except UnicodeEncodeError as error:
        raise InventoryError("libtest output is not valid UTF-8") from error


def _text_output(output: bytes | str) -> str:
    try:
        return _raw_output(output).decode("utf-8")
    except UnicodeDecodeError as error:
        raise InventoryError("toolchain output is not valid UTF-8") from error


def _list_command(record: dict) -> tuple[str, ...]:
    return ("cargo", "test", "--locked", "-p", record["package"], "--test", record["integration_target"], "--", "--list")


def _exact_command(record: dict) -> tuple[str, ...]:
    return ("cargo", "test", "--locked", "-p", record["package"], "--test", record["integration_target"], record["fully_qualified_test_name"], "--", "--exact")


def verify_record(record: dict, command: Command = subprocess_command) -> None:
    validate_record(record)
    if record.get("selector_status") != "RESOLVED":
        raise InventoryError(f"record {record['id']} is UNRESOLVED")
    listing = _raw_output(command(_list_command(record)))
    try:
        listed = parse_libtest_list(listing)
    except Phase3InventoryError as error:
        raise InventoryError(f"record {record['id']} libtest list invalid: {error}") from error
    selector = record["fully_qualified_test_name"]
    if listed.count(selector) != 1:
        raise InventoryError(f"record {record['id']} selector is not exactly one listed test")
    if hashlib.sha256(listing).hexdigest() != record["list_digest"]:
        raise InventoryError(f"record {record['id']} list digest changed")
    if _text_output(command(("rustc", "-V"))).strip() != record["toolchain"]:
        raise InventoryError(f"record {record['id']} toolchain changed")
    try:
        verify_exact_execution((selector,), _raw_output(command(_exact_command(record))))
    except Phase3InventoryError as error:
        raise InventoryError(
            f"record {record['id']} exact run has invalid libtest output: {error}"
        ) from error


def verify_frozen_all(document: dict, command: Command = subprocess_command) -> None:
    validate_inventory(document)
    if document["inventory_status"] != "FROZEN":
        raise InventoryError("--verify-frozen-all requires FROZEN inventory")
    records = sorted((record for record in document["records"] if rust_record(record)), key=lambda record: record["id"])
    completed: set[str] = set()
    for record in records:
        verify_record(record, command)
        completed.add(record["id"])
    if completed != {record["id"] for record in records}:
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
        if document["inventory_status"] != "FROZEN":
            raise InventoryError("external verification requires FROZEN inventory")
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
