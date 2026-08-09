#!/usr/bin/env python3
"""Issue and consume one-shot, candidate-local CI input receipts."""
from __future__ import annotations
import argparse
import hashlib
import os
import secrets
import stat
import time
from pathlib import Path
from scripts.rc0_candidate.git_inspection import GitInspectionError, run_repository_git
from scripts.rc0_candidate.verify_rust_inventory import InventoryError, _valid_toolchain, validate_inventory
from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical
_SCHEMA = "gocode.local-input-receipt/1"
_COMPLETE = "LOCAL_INPUTS_COMPLETE"
_INVENTORIES = {
    "source_candidate": "scripts/rc0_candidate/inventories/source-candidate-v1.json",
    "phase3": "scripts/rc0_candidate/inventories/phase3-v1.json",
    "local_reliability": "scripts/rc0_candidate/inventories/local-reliability-v1.json",
    "taxonomy_migration": "docs/rc0/taxonomy-migration-v1.json",
}
_GATES = ("local-structural", "runtime-pinned", "runtime-msrv", "frontend", "documentation-architecture")

class LocalInputReceiptError(ValueError):
    """The local receipt is unsafe, stale, malformed, or already consumed."""
def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def _read_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LocalInputReceiptError(f"input is unavailable: {path.name}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 1_048_576:
            raise LocalInputReceiptError(f"input is not a bounded regular file: {path.name}")
        raw = b""
        while chunk := os.read(descriptor, 1 << 20):
            raw += chunk
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_size,
            item.st_mtime_ns, item.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(before) != identity(current):
            raise LocalInputReceiptError(f"input changed while read: {path.name}")
        return raw
    except OSError as error:
        raise LocalInputReceiptError(f"input is unavailable: {path.name}") from error
    finally:
        os.close(descriptor)

def _inventory_state(root: Path, selected_inventory: Path | None = None) -> dict[str, str]:
    paths = {name: root / relative for name, relative in _INVENTORIES.items()}
    if selected_inventory is not None:
        paths["source_candidate"] = selected_inventory
    raw = {name: _read_regular(path) for name, path in paths.items()}
    try:
        source = loads_canonical(raw["source_candidate"])
        phase3 = loads_canonical(raw["phase3"])
        reliability = loads_canonical(raw["local_reliability"])
        taxonomy = loads_canonical(raw["taxonomy_migration"])
        validate_inventory(source)
    except (StrictJSONError, InventoryError) as error:
        raise LocalInputReceiptError("inventory validation failed") from error
    if source.get("inventory_status") != "FROZEN":
        raise LocalInputReceiptError("source inventory is not FROZEN")
    phase3_records = sorted(
        (record for record in source["records"] if record["id"].startswith("phase3.")),
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
    entries = reliability.get("entries") if isinstance(reliability, dict) else None
    if (
        not isinstance(reliability, dict)
        or set(reliability) != {"schema", "entries"}
        or reliability.get("schema") != "gocode.local-reliability-inventory/1"
        or not isinstance(entries, list)
        or not entries
        or any(
            not isinstance(entry, dict)
            or set(entry) != {"category", "package", "target", "fully_qualified_test_name"}
            or entry.get("category") not in {"recovery", "telemetry"}
            or not all(isinstance(value, str) and value for value in entry.values())
            for entry in entries
        )
    ):
        raise LocalInputReceiptError("local reliability inventory is invalid")
    fields = ("category", "package", "target", "fully_qualified_test_name")
    identities = [tuple(entry[field] for field in fields) for entry in entries]
    if len(identities) != len(set(identities)) or not isinstance(taxonomy, dict):
        raise LocalInputReceiptError("named inventory contains duplicate or invalid entries")
    return {
        **{f"{name}_sha256": _digest(value) for name, value in raw.items()},
        "frozen_inventory_digest": source["final_inventory_digest"],
    }

def _source_state(root: Path) -> dict[str, str]:
    try:
        first = run_repository_git(root, "rev-parse", "HEAD").decode("ascii").strip()
        tree = run_repository_git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
        status = run_repository_git(
            root, "status", "--porcelain=v1", "-z", "--untracked-files=all",
            "--ignore-submodules=none",
        )
        second = run_repository_git(root, "rev-parse", "HEAD").decode("ascii").strip()
    except (GitInspectionError, OSError, UnicodeDecodeError) as error:
        raise LocalInputReceiptError("source identity is unavailable") from error
    if status or first != second:
        raise LocalInputReceiptError("source is dirty or changed during receipt capture")
    return {"source_revision": first, "source_tree": tree}

def _private_parent(path: Path) -> tuple[int, str]:
    path = path.absolute()
    if path.name in {"", ".", ".."} or path.parent.resolve(strict=True) != path.parent:
        raise LocalInputReceiptError("receipt path is unsafe")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path.parent, flags)
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise LocalInputReceiptError("receipt parent is unavailable") from error
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise LocalInputReceiptError("receipt parent is not owner-private mode 0700")
    return descriptor, path.name

def _atomic_write(path: Path, raw: bytes) -> None:
    parent_fd, name = _private_parent(path)
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        view = memoryview(raw)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as error:
        raise LocalInputReceiptError("receipt cannot be atomically published") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)

def issue_local_input_receipt(
    root: Path, receipt: Path, input_script: Path, pinned_rustc: str, msrv_rustc: str,
) -> dict:
    root = root.resolve(strict=True)
    if not _valid_toolchain(pinned_rustc) or not _valid_toolchain(msrv_rustc):
        raise LocalInputReceiptError("toolchain identity is not canonical")
    script_raw = _read_regular(input_script)
    record = {
        "schema": _SCHEMA,
        "receipt_nonce": secrets.token_hex(32),
        "issued_at_unix": int(time.time()),
        "local_inputs": _COMPLETE,
        **_source_state(root),
        "input_script_sha256": _digest(script_raw),
        "inventories": _inventory_state(root),
        "toolchains": {"pinned": pinned_rustc, "msrv": msrv_rustc},
        "gate_results": [{"gate": gate, "result": "SATISFIED"} for gate in _GATES],
    }
    _atomic_write(receipt, canonical_bytes(record))
    return record

def _load_receipt(path: Path) -> tuple[dict, int, int, str]:
    parent_fd, name = _private_parent(path)
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > 65_536
        ):
            raise LocalInputReceiptError("receipt file is not owner-private")
        raw = b""
        while chunk := os.read(descriptor, 65_537 - len(raw)):
            raw += chunk
            if len(raw) > 65_536:
                raise LocalInputReceiptError("receipt is oversized")
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if identity(metadata) != identity(os.fstat(descriptor)) or identity(metadata) != identity(current):
            raise LocalInputReceiptError("receipt changed while read")
        record = loads_canonical(raw)
        if not isinstance(record, dict) or canonical_bytes(record) != raw:
            raise LocalInputReceiptError("receipt is not canonical")
        return record, parent_fd, descriptor, name
    except (OSError, StrictJSONError, LocalInputReceiptError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
        raise LocalInputReceiptError("receipt is unavailable or invalid") from error

def validate_local_input_receipt(
    root: Path, receipt: Path, input_script: Path, inventory: Path, *, consume: bool = False,
) -> dict:
    root = root.resolve(strict=True)
    inventory = inventory.resolve(strict=True)
    expected_inventory = (root / _INVENTORIES["source_candidate"]).resolve(strict=True)
    if inventory != expected_inventory:
        raise LocalInputReceiptError("source inventory path is not canonical")
    record, parent_fd, descriptor, name = _load_receipt(receipt)
    try:
        expected = {
            "schema", "receipt_nonce", "issued_at_unix", "local_inputs",
            "source_revision", "source_tree",
            "input_script_sha256", "inventories", "toolchains", "gate_results",
        }
        source = _source_state(root)
        inventory_state = _inventory_state(root, inventory)
        script_digest = _digest(_read_regular(input_script))
        valid_gates = [{"gate": gate, "result": "SATISFIED"} for gate in _GATES]
        if (
            set(record) != expected
            or record.get("schema") != _SCHEMA
            or record.get("local_inputs") != _COMPLETE
            or not isinstance(record.get("receipt_nonce"), str)
            or len(record["receipt_nonce"]) != 64
            or any(character not in "0123456789abcdef" for character in record["receipt_nonce"])
            or not isinstance(record.get("issued_at_unix"), int)
            or not 0 <= int(time.time()) - record["issued_at_unix"] <= 3_600
            or record.get("source_revision") != source["source_revision"]
            or record.get("source_tree") != source["source_tree"]
            or record.get("input_script_sha256") != script_digest
            or record.get("inventories") != inventory_state
            or record.get("gate_results") != valid_gates
            or set(record.get("toolchains", {})) != {"pinned", "msrv"}
            or not all(_valid_toolchain(value) for value in record["toolchains"].values())
        ):
            raise LocalInputReceiptError("receipt source, inventory, toolchain, or gate binding is stale")
        if consume:
            os.unlink(name, dir_fd=parent_fd)
            if os.fstat(descriptor).st_nlink != 0:
                raise LocalInputReceiptError("receipt path changed before one-shot consumption")
            os.fsync(parent_fd)
        return record
    finally:
        os.close(descriptor)
        os.close(parent_fd)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("issue", "validate"))
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--input-script", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, default=Path(_INVENTORIES["source_candidate"]))
    parser.add_argument("--pinned-rustc")
    parser.add_argument("--msrv-rustc")
    args = parser.parse_args()
    root = Path.cwd()
    try:
        if args.action == "issue":
            if not args.pinned_rustc or not args.msrv_rustc:
                raise LocalInputReceiptError("issue requires both toolchain identities")
            issue_local_input_receipt(
                root, args.receipt, args.input_script, args.pinned_rustc, args.msrv_rustc,
            )
        else:
            validate_local_input_receipt(root, args.receipt, args.input_script, args.inventory)
    except (LocalInputReceiptError, OSError):
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
