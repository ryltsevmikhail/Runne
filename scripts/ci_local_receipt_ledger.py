"""Durable one-shot nonce claims anchored to a Git worktree identity."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError, file_identity
from scripts.rc0_candidate.git_inspection import GitInspectionError, run_repository_git
from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical


_LEDGER = "gocode-local-input-nonces-v1"
_SCHEMA = "gocode.local-input-consumed-nonce/1"


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _repository_location(root: Path) -> tuple[Path, dict[str, int]]:
    try:
        raw = run_repository_git(root, "rev-parse", "--path-format=absolute", "--git-dir")
        git_dir = Path(raw.decode("utf-8").strip())
        canonical = git_dir.resolve(strict=True)
        root_metadata = os.stat(root, follow_symlinks=False)
        git_metadata = os.stat(canonical, follow_symlinks=False)
    except (GitInspectionError, OSError, UnicodeDecodeError) as error:
        raise LocalInputReceiptError("nonce ledger repository identity is unavailable") from error
    if git_dir.absolute() != canonical:
        raise LocalInputReceiptError("nonce ledger Git directory is not canonical")
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or not stat.S_ISDIR(git_metadata.st_mode)
        or git_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(git_metadata.st_mode) & 0o022
    ):
        raise LocalInputReceiptError("nonce ledger Git directory is unsafe")
    return canonical, {
        "worktree_dev": root_metadata.st_dev,
        "worktree_ino": root_metadata.st_ino,
        "git_dir_dev": git_metadata.st_dev,
        "git_dir_ino": git_metadata.st_ino,
    }


def repository_identity(root: Path) -> dict[str, int]:
    return _repository_location(root)[1]


def _open_ledger(root: Path) -> tuple[int, dict[str, int]]:
    git_dir, identity = _repository_location(root)
    git_fd = ledger_fd = -1
    try:
        git_fd = os.open(git_dir, _directory_flags())
        opened_git = os.fstat(git_fd)
        if (
            opened_git.st_dev != identity["git_dir_dev"]
            or opened_git.st_ino != identity["git_dir_ino"]
        ):
            raise LocalInputReceiptError("nonce ledger Git directory identity changed")
        try:
            os.mkdir(_LEDGER, 0o700, dir_fd=git_fd)
            os.fsync(git_fd)
        except FileExistsError:
            pass
        ledger_fd = os.open(_LEDGER, _directory_flags(), dir_fd=git_fd)
        metadata = os.fstat(ledger_fd)
        current = os.stat(_LEDGER, dir_fd=git_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or file_identity(metadata) != file_identity(current)
        ):
            raise LocalInputReceiptError("nonce ledger directory is unsafe")
        return ledger_fd, identity
    except (OSError, LocalInputReceiptError) as error:
        if ledger_fd >= 0:
            os.close(ledger_fd)
        raise LocalInputReceiptError("nonce ledger is unavailable or unsafe") from error
    finally:
        if git_fd >= 0:
            os.close(git_fd)


def _existing_claim_is_valid(ledger_fd: int, name: str, expected: bytes) -> bool:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, dir_fd=ledger_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > 4_096
        ):
            return False
        raw = b""
        while chunk := os.read(descriptor, 4_097 - len(raw)):
            raw += chunk
            if len(raw) > 4_096:
                return False
        current = os.stat(name, dir_fd=ledger_fd, follow_symlinks=False)
        if file_identity(metadata) != file_identity(os.fstat(descriptor)):
            return False
        if file_identity(metadata) != file_identity(current):
            return False
        record = loads_canonical(raw)
        return isinstance(record, dict) and canonical_bytes(record) == raw and raw == expected
    except (OSError, StrictJSONError, TypeError, ValueError, KeyError):
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def claim_consumed_nonce(root: Path, nonce: str) -> None:
    ledger_fd, identity = _open_ledger(root)
    name = f"{nonce}.json"
    raw = canonical_bytes(
        {"schema": _SCHEMA, "receipt_nonce": nonce, "repository_identity": identity}
    )
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=ledger_fd)
        except FileExistsError as error:
            if not _existing_claim_is_valid(ledger_fd, name, raw):
                raise LocalInputReceiptError("consumed nonce ledger entry is corrupt") from error
            raise LocalInputReceiptError("receipt nonce was already consumed") from error
        view = memoryview(raw)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        current = os.stat(name, dir_fd=ledger_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or file_identity(metadata) != file_identity(current)
        ):
            raise LocalInputReceiptError("consumed nonce claim changed during publication")
        os.fsync(ledger_fd)
    except (OSError, LocalInputReceiptError) as error:
        raise LocalInputReceiptError("receipt nonce could not be claimed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(ledger_fd)
