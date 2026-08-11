#!/usr/bin/env python3
"""Run canonical local gates and validate their one-shot receipt."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import time
from pathlib import Path
from typing import Sequence

from scripts.ci_local_receipt_common import (
    COMPLETE,
    GATES,
    INVENTORIES,
    SCHEMA,
    LocalInputReceiptError,
    file_identity,
    private_parent,
)
from scripts.ci_local_receipt_ledger import claim_consumed_nonce
from scripts.ci_local_receipt_runtime import valid_executable_shape
from scripts.ci_local_receipt_state import (
    capture_bound_state,
    run_local_input_gates,
)
from scripts.rc0_candidate.verify_rust_inventory import _valid_toolchain
from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical


_EXPECTED_FIELDS = {
    "schema",
    "receipt_nonce",
    "issued_at_unix",
    "local_inputs",
    "source_revision",
    "source_tree",
    "repository_identity",
    "git_metadata_sha256",
    "input_script_sha256",
    "inventories",
    "executables",
    "toolchains",
    "gate_exit_status",
    "gate_results",
}
_INVENTORY_FIELDS = {
    "source_candidate_sha256",
    "phase3_sha256",
    "local_reliability_sha256",
    "taxonomy_migration_sha256",
    "frozen_inventory_digest",
}
_REPOSITORY_FIELDS = {
    "worktree_dev", "worktree_ino", "git_dir_dev", "git_dir_ino"
}


def _hex(value: object, lengths: tuple[int, ...]) -> bool:
    return (
        isinstance(value, str)
        and len(value) in lengths
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_shape(record: object) -> bool:
    if not isinstance(record, dict) or set(record) != _EXPECTED_FIELDS:
        return False
    if (
        record["schema"] != SCHEMA
        or record["local_inputs"] != COMPLETE
        or not _hex(record["receipt_nonce"], (64,))
        or type(record["issued_at_unix"]) is not int
        or not _hex(record["source_revision"], (40, 64))
        or not _hex(record["source_tree"], (40, 64))
        or not _hex(record["git_metadata_sha256"], (64,))
        or not _hex(record["input_script_sha256"], (64,))
        or type(record["gate_exit_status"]) is not int
        or record["gate_exit_status"] != 0
    ):
        return False
    inventories = record["inventories"]
    repository = record["repository_identity"]
    if (
        not isinstance(repository, dict)
        or set(repository) != _REPOSITORY_FIELDS
        or not all(type(value) is int and value >= 0 for value in repository.values())
    ):
        return False
    if (
        not isinstance(inventories, dict)
        or set(inventories) != _INVENTORY_FIELDS
        or not all(_hex(value, (64,)) for value in inventories.values())
    ):
        return False
    toolchains = record["toolchains"]
    if (
        not valid_executable_shape(record["executables"])
        or
        not isinstance(toolchains, dict)
        or set(toolchains) != {"pinned", "msrv"}
        or not all(isinstance(value, str) and _valid_toolchain(value) for value in toolchains.values())
        or toolchains["pinned"].split()[1] != "1.97.1"
        or toolchains["msrv"].split()[1] != "1.95.0"
    ):
        return False
    gates = record["gate_results"]
    if not isinstance(gates, list) or len(gates) != len(GATES):
        return False
    for expected, gate in zip(GATES, gates, strict=True):
        if (
            not isinstance(gate, dict)
            or set(gate) != {"gate", "result"}
            or not isinstance(gate["gate"], str)
            or not isinstance(gate["result"], str)
            or gate != {"gate": expected, "result": "SATISFIED"}
        ):
            return False
    return True


def _load_receipt(path: Path) -> tuple[dict, int, int, str]:
    parent_fd, name = private_parent(path)
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
        chunks: list[bytes] = []
        remaining = 65_537
        while remaining and (chunk := os.read(descriptor, min(remaining, 1 << 16))):
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > 65_536:
            raise LocalInputReceiptError("receipt is oversized")
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if file_identity(metadata) != file_identity(os.fstat(descriptor)):
            raise LocalInputReceiptError("receipt changed while read")
        if file_identity(metadata) != file_identity(current):
            raise LocalInputReceiptError("receipt changed while read")
        record = loads_canonical(raw)
        if not isinstance(record, dict) or canonical_bytes(record) != raw:
            raise LocalInputReceiptError("receipt is not canonical")
        return record, parent_fd, descriptor, name
    except (
        OSError,
        StrictJSONError,
        LocalInputReceiptError,
        TypeError,
        ValueError,
        KeyError,
    ) as error:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
        raise LocalInputReceiptError("receipt is unavailable or invalid") from error


def validate_local_input_receipt(
    root: Path, receipt: Path, inventory: Path, *, consume: bool = False
) -> dict:
    root = root.resolve(strict=True)
    record, parent_fd, descriptor, name = _load_receipt(receipt)
    try:
        if not _valid_shape(record):
            raise LocalInputReceiptError("receipt shape is invalid")
        age = int(time.time()) - record["issued_at_unix"]
        expected_inventory = (root / INVENTORIES["source_candidate"]).resolve(strict=True)
        if inventory.resolve(strict=True) != expected_inventory:
            raise LocalInputReceiptError("source inventory path is not canonical")
        bound = capture_bound_state(root)
        if (
            not 0 <= age <= 3_600
            or any(record[field] != value for field, value in bound.items())
        ):
            raise LocalInputReceiptError("receipt source or input binding is stale")
        if consume:
            claim_consumed_nonce(root, record["receipt_nonce"])
            os.unlink(name, dir_fd=parent_fd)
            if os.fstat(descriptor).st_nlink != 0:
                raise LocalInputReceiptError("receipt path changed before one-shot consumption")
            os.fsync(parent_fd)
        return record
    except LocalInputReceiptError:
        raise
    except (OSError, TypeError, ValueError, KeyError) as error:
        raise LocalInputReceiptError("receipt validation failed") from error
    finally:
        os.close(descriptor)
        os.close(parent_fd)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise LocalInputReceiptError(message)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = _Parser(add_help=False)
    parser.add_argument("action", choices=("run", "validate"))
    parser.add_argument("--receipt", type=Path, required=True)
    try:
        args = parser.parse_args(sys.argv[1:] if arguments is None else arguments)
        root = Path.cwd()
        if args.action == "run":
            run_local_input_gates(root, args.receipt)
        else:
            validate_local_input_receipt(
                root, args.receipt, root / INVENTORIES["source_candidate"]
            )
    except (LocalInputReceiptError, OSError, TypeError, ValueError, KeyError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
