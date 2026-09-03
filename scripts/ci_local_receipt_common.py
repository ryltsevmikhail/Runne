"""Shared fail-closed primitives for local CI receipts."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path

from scripts.ci_local_path_alias import is_standard_macos_var_alias


SCHEMA = "gocode.local-input-receipt/1"
COMPLETE = "LOCAL_INPUTS_COMPLETE"
INPUT_SCRIPT = "scripts/ci-local-inputs.sh"
INVENTORIES = {
    "source_candidate": "scripts/rc0_candidate/inventories/source-candidate-v1.json",
    "phase3": "scripts/rc0_candidate/inventories/phase3-v1.json",
    "local_reliability": "scripts/rc0_candidate/inventories/local-reliability-v1.json",
    "taxonomy_migration": "docs/rc0/taxonomy-migration-v1.json",
}
GATES = (
    "local-structural",
    "runtime-pinned",
    "runtime-msrv",
    "frontend",
    "documentation-architecture",
)


class LocalInputReceiptError(ValueError):
    """The local receipt is unsafe, stale, malformed, or already consumed."""


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_regular(path: Path, limit: int = 1_048_576) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LocalInputReceiptError(f"input is unavailable: {path.name}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise LocalInputReceiptError(f"input is not a bounded regular file: {path.name}")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining and (chunk := os.read(descriptor, min(remaining, 1 << 20))):
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if len(raw) > limit or file_identity(before) != file_identity(after):
            raise LocalInputReceiptError(f"input changed while read: {path.name}")
        if file_identity(before) != file_identity(current):
            raise LocalInputReceiptError(f"input changed while read: {path.name}")
        return raw
    except OSError as error:
        raise LocalInputReceiptError(f"input is unavailable: {path.name}") from error
    finally:
        os.close(descriptor)


def file_identity(item: os.stat_result) -> tuple[int, ...]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def private_parent(path: Path) -> tuple[int, str]:
    path = path.absolute()
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise LocalInputReceiptError("receipt parent is unavailable") from error
    if path.name in {"", ".", ".."} or (
        parent != path.parent
        and not is_standard_macos_var_alias(path.parent, parent)
    ):
        raise LocalInputReceiptError("receipt path is unsafe")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(parent, flags)
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise LocalInputReceiptError("receipt parent is unavailable") from error
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise LocalInputReceiptError("receipt parent is not owner-private mode 0700")
    return descriptor, path.name


def atomic_write(path: Path, raw: bytes) -> None:
    parent_fd, name = private_parent(path)
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        view = memoryview(raw)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(
            temporary,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
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
