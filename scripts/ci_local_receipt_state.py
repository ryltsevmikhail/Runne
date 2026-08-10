"""Canonical repository state capture and local-gate orchestration."""

from __future__ import annotations

import secrets
import subprocess
import time
from pathlib import Path

from scripts.ci_local_receipt_common import (
    COMPLETE,
    GATES,
    INPUT_SCRIPT,
    INVENTORIES,
    SCHEMA,
    LocalInputReceiptError,
    atomic_write,
    digest,
    read_regular,
)
from scripts.ci_local_receipt_ledger import repository_identity
from scripts.ci_local_receipt_runtime import (
    TrustedRuntime,
    resolve_trusted_runtime,
)
from scripts.rc0_candidate.git_inspection import GitInspectionError, run_repository_git
from scripts.rc0_candidate.verify_rust_inventory import (
    InventoryError,
    validate_inventory,
)
from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical


def _git(root: Path, *arguments: str) -> bytes:
    try:
        return run_repository_git(root, *arguments)
    except (GitInspectionError, OSError, UnicodeDecodeError) as error:
        raise LocalInputReceiptError("source identity is unavailable") from error


def source_state(root: Path) -> dict[str, str]:
    first = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    second = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if status or first != second:
        raise LocalInputReceiptError("source is dirty or changed during receipt capture")
    return {"source_revision": first, "source_tree": tree}


def _tracked_bytes(root: Path, relative: str) -> bytes:
    actual = read_regular(root / relative)
    tracked = _git(root, "show", f"HEAD:{relative}")
    if actual != tracked:
        raise LocalInputReceiptError(f"canonical tracked input changed: {relative}")
    return actual


def inventory_state(root: Path, selected_inventory: Path | None = None) -> dict[str, str]:
    paths = dict(INVENTORIES)
    if selected_inventory is not None:
        expected = (root / INVENTORIES["source_candidate"]).resolve(strict=True)
        if selected_inventory.resolve(strict=True) != expected:
            raise LocalInputReceiptError("source inventory path is not canonical")
    raw = {name: _tracked_bytes(root, relative) for name, relative in paths.items()}
    try:
        source = loads_canonical(raw["source_candidate"])
        phase3 = loads_canonical(raw["phase3"])
        reliability = loads_canonical(raw["local_reliability"])
        taxonomy = loads_canonical(raw["taxonomy_migration"])
        validate_inventory(source)
        if not isinstance(source, dict) or source.get("inventory_status") != "FROZEN":
            raise LocalInputReceiptError("source inventory is not FROZEN")
        records = source.get("records")
        if not isinstance(records, list):
            raise LocalInputReceiptError("source inventory records are invalid")
        phase3_records = sorted(
            (record for record in records if record["id"].startswith("phase3.")),
            key=lambda record: record["id"],
        )
        if (
            not isinstance(phase3, dict)
            or set(phase3) != {"schema", "source_inventory_digest", "entries"}
            or phase3.get("schema") != "gocode.phase3-inventory/1"
            or phase3.get("source_inventory_digest") != source["final_inventory_digest"]
            or phase3.get("entries") != phase3_records
        ):
            raise LocalInputReceiptError("phase3 inventory does not match frozen inventory")
        _validate_reliability(reliability)
        if not isinstance(taxonomy, dict):
            raise LocalInputReceiptError("taxonomy migration is invalid")
    except (
        StrictJSONError,
        InventoryError,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ) as error:
        raise LocalInputReceiptError("inventory validation failed") from error
    return {
        **{f"{name}_sha256": digest(value) for name, value in raw.items()},
        "frozen_inventory_digest": source["final_inventory_digest"],
    }


def _validate_reliability(reliability: object) -> None:
    entries = reliability.get("entries") if isinstance(reliability, dict) else None
    expected = {"category", "package", "target", "fully_qualified_test_name"}
    if (
        not isinstance(reliability, dict)
        or set(reliability) != {"schema", "entries"}
        or reliability.get("schema") != "gocode.local-reliability-inventory/1"
        or not isinstance(entries, list)
        or not entries
        or any(
            not isinstance(entry, dict)
            or set(entry) != expected
            or entry.get("category") not in {"recovery", "telemetry"}
            or not all(isinstance(value, str) and value for value in entry.values())
            for entry in entries
        )
    ):
        raise LocalInputReceiptError("local reliability inventory is invalid")
    fields = ("category", "package", "target", "fully_qualified_test_name")
    identities = [tuple(entry[field] for field in fields) for entry in entries]
    if len(identities) != len(set(identities)):
        raise LocalInputReceiptError("named inventory contains duplicate entries")


def capture_bound_state(root: Path, runtime: TrustedRuntime | None = None) -> dict:
    runtime = resolve_trusted_runtime() if runtime is None else runtime
    script_raw = _tracked_bytes(root, INPUT_SCRIPT)
    return {
        **source_state(root),
        "repository_identity": repository_identity(root),
        "input_script_sha256": digest(script_raw),
        "inventories": inventory_state(root),
        "executables": runtime.executables,
        "toolchains": runtime.toolchains,
    }


def run_local_input_gates(root: Path, receipt: Path) -> dict:
    root = root.resolve(strict=True)
    pre_runtime = resolve_trusted_runtime()
    pre_gate = capture_bound_state(root, pre_runtime)
    try:
        completed = subprocess.run(
            (pre_runtime.bash, root / INPUT_SCRIPT),
            cwd=root,
            env=pre_runtime.environment,
            check=False,
        )
    except OSError as error:
        raise LocalInputReceiptError("canonical local input gate could not run") from error
    if type(completed.returncode) is not int or completed.returncode != 0:
        raise LocalInputReceiptError("canonical local input gate did not pass")
    post_gate = capture_bound_state(root, resolve_trusted_runtime())
    if pre_gate != post_gate:
        raise LocalInputReceiptError("bound source or inputs changed during local gate")
    record = {
        "schema": SCHEMA,
        "receipt_nonce": secrets.token_hex(32),
        "issued_at_unix": int(time.time()),
        "local_inputs": COMPLETE,
        **post_gate,
        "gate_exit_status": completed.returncode,
        "gate_results": [{"gate": gate, "result": "SATISFIED"} for gate in GATES],
    }
    atomic_write(receipt, canonical_bytes(record))
    return record
