"""Authenticated staging-name recovery for interrupted evidence construction."""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import re
import stat
from dataclasses import dataclass
from typing import Mapping

from .publish_fs import DIRECTORY, OWNER_XATTR, entry_state, read_regular

_ATTEMPT = re.compile(
    r"\.([0-9a-f]{40})\.([0-9a-f]{32})\.([0-9a-f]{64})\.attempt"
)


class RecoveryError(ValueError):
    pass


_ABSENT_XATTR_ERRNOS = {
    value for value in (getattr(errno, "ENODATA", None), getattr(errno, "ENOATTR", None))
    if value is not None
}


@dataclass(frozen=True)
class OwnedBlob:
    state: tuple[int, ...]
    data: bytes


@dataclass(frozen=True)
class _CleanupEntry:
    name: str
    state: tuple[int, ...]
    data: bytes


@dataclass(frozen=True)
class _CleanupPlan:
    directory_state: tuple[int, ...]
    owner: bytes | None
    entries: tuple[_CleanupEntry, ...]
    completion_marker: str | None


def attempt_name(source_sha: str, owner_id: bytes, nonce: str) -> str:
    message = source_sha.encode("ascii") + b"\0" + nonce.encode("ascii")
    tag = hmac.new(owner_id, message, hashlib.sha256).hexdigest()
    return f".{source_sha}.{nonce}.{tag}.attempt"


def authenticated_attempt(name: str, source_sha: str, owner_id: bytes) -> bool:
    match = _ATTEMPT.fullmatch(name)
    if match is None or match.group(1) != source_sha:
        return False
    expected = attempt_name(source_sha, owner_id, match.group(2))
    return hmac.compare_digest(name, expected)


def _directory_safe(fd: int) -> tuple[int, ...]:
    metadata = os.fstat(fd)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise RecoveryError("owned construction directory mode is unsafe")
    return entry_state(metadata)


def validate_blob_set(
    directory_fd: int, blobs: Mapping[str, bytes], *, exact: bool
) -> dict[str, tuple[int, ...]]:
    names = set(os.listdir(directory_fd))
    expected = set(blobs)
    if not names.issubset(expected) or (exact and names != expected):
        raise RecoveryError("construction directory contains unexpected entries")
    states: dict[str, tuple[int, ...]] = {}
    for name in names:
        data, state = read_regular(directory_fd, name)
        if data != blobs[name]:
            raise RecoveryError("construction directory blob content changed")
        states[name] = state
    return states


def _require_absent(root_fd: int, name: str | None) -> None:
    if name is None:
        return
    try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise RecoveryError("completion marker blocks construction cleanup")


def _owner_xattr(directory_fd: int) -> bytes | None:
    try:
        return os.getxattr(directory_fd, OWNER_XATTR)
    except OSError as error:
        if error.errno in _ABSENT_XATTR_ERRNOS:
            return None
        raise RecoveryError("construction directory owner identity is unreadable") from error


def _collect_cleanup_plan(
    root_fd: int, name: str, directory_fd: int, state: tuple[int, ...],
    blobs: Mapping[str, bytes], owner_id: bytes, *,
    owned_blobs: Mapping[str, OwnedBlob] | None = None,
    completion_marker: str | None = None, allow_unbound_empty: bool = False,
) -> _CleanupPlan:
    if _directory_safe(directory_fd) != state:
        raise RecoveryError("held construction directory identity changed")
    owner = _owner_xattr(directory_fd)
    names = tuple(sorted(os.listdir(directory_fd), key=os.fsencode))
    if owner != owner_id:
        if not allow_unbound_empty or owner is not None or names:
            raise RecoveryError("construction directory owner identity changed")
    name_set = set(names)
    if not name_set.issubset(blobs):
        raise RecoveryError("owned construction directory has foreign entries")
    if owned_blobs is not None and name_set != set(owned_blobs):
        raise RecoveryError("owned construction directory identity set changed")
    path = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    if entry_state(path) != state:
        raise RecoveryError("owned construction directory pathname changed")
    _require_absent(root_fd, completion_marker)
    entries = []
    for filename in names:
        data, blob_state = read_regular(directory_fd, filename)
        expected_data = (
            owned_blobs[filename].data if owned_blobs is not None else blobs[filename]
        )
        expected_state = owned_blobs[filename].state if owned_blobs is not None else None
        if data != expected_data or (expected_state is not None and blob_state != expected_state):
            raise RecoveryError("owned construction blob content or identity changed")
        entries.append(_CleanupEntry(filename, blob_state, data))
    return _CleanupPlan(state, owner, tuple(entries), completion_marker)


def _validate_cleanup_plan(
    root_fd: int, name: str, directory_fd: int, plan: _CleanupPlan,
) -> None:
    if (
        _directory_safe(directory_fd) != plan.directory_state
        or entry_state(os.stat(name, dir_fd=root_fd, follow_symlinks=False))
        != plan.directory_state
        or _owner_xattr(directory_fd) != plan.owner
        or tuple(sorted(os.listdir(directory_fd), key=os.fsencode))
        != tuple(entry.name for entry in plan.entries)
    ):
        raise RecoveryError("owned construction directory changed before cleanup")
    _require_absent(root_fd, plan.completion_marker)
    for entry in plan.entries:
        data, state = read_regular(directory_fd, entry.name)
        if data != entry.data or state != entry.state:
            raise RecoveryError("owned construction blob changed before cleanup")
    if (
        _directory_safe(directory_fd) != plan.directory_state
        or entry_state(os.stat(name, dir_fd=root_fd, follow_symlinks=False))
        != plan.directory_state
        or tuple(sorted(os.listdir(directory_fd), key=os.fsencode))
        != tuple(entry.name for entry in plan.entries)
    ):
        raise RecoveryError("owned construction directory changed before cleanup")
    _require_absent(root_fd, plan.completion_marker)
    if _owner_xattr(directory_fd) != plan.owner:
        raise RecoveryError("construction directory owner identity changed before deletion")


def _execute_cleanup_plan(
    root_fd: int, name: str, directory_fd: int, plan: _CleanupPlan,
) -> None:
    for entry in plan.entries:
        current = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
        if entry_state(current) != entry.state:
            raise RecoveryError("owned construction blob changed during cleanup")
        os.unlink(entry.name, dir_fd=directory_fd)
    if (
        _directory_safe(directory_fd) != plan.directory_state
        or entry_state(os.stat(name, dir_fd=root_fd, follow_symlinks=False))
        != plan.directory_state
    ):
        raise RecoveryError("owned construction directory changed during cleanup")
    os.rmdir(name, dir_fd=root_fd)


def _remove_bound_directory(
    root_fd: int, name: str, directory_fd: int, state: tuple[int, ...],
    blobs: Mapping[str, bytes], owner_id: bytes, *,
    owned_blobs: Mapping[str, OwnedBlob] | None = None,
    completion_marker: str | None = None, allow_unbound_empty: bool = False,
) -> None:
    plan = _collect_cleanup_plan(
        root_fd, name, directory_fd, state, blobs, owner_id,
        owned_blobs=owned_blobs, completion_marker=completion_marker,
        allow_unbound_empty=allow_unbound_empty,
    )
    _validate_cleanup_plan(root_fd, name, directory_fd, plan)
    _execute_cleanup_plan(root_fd, name, directory_fd, plan)


def cleanup_held_attempt(
    root_fd: int, directory_fd: int, state: tuple[int, ...], source_sha: str,
    owner_id: bytes, blobs: Mapping[str, bytes], *,
    owned_blobs: Mapping[str, OwnedBlob] | None = None,
    allow_unbound_empty: bool = False,
) -> None:
    matches = []
    for name in os.listdir(root_fd):
        try:
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if entry_state(current) == state:
            matches.append(name)
    if len(matches) != 1:
        raise RecoveryError("held construction directory pathname is unavailable")
    _remove_bound_directory(
        root_fd, matches[0], directory_fd, state, blobs, owner_id,
        owned_blobs=owned_blobs,
        completion_marker=f".{source_sha}.complete" if matches[0] == source_sha else None,
        allow_unbound_empty=allow_unbound_empty,
    )


def recover_attempts(
    root_fd: int, source_sha: str, owner_id: bytes, blobs: Mapping[str, bytes]
) -> None:
    suffix = ".attempt"
    prefix = f".{source_sha}."
    for name in tuple(os.listdir(root_fd)):
        if not name.startswith(prefix) or not name.endswith(suffix):
            continue
        if not authenticated_attempt(name, source_sha, owner_id):
            raise RecoveryError("foreign construction attempt blocks recovery")
        descriptor = os.open(name, DIRECTORY, dir_fd=root_fd)
        try:
            state = _directory_safe(descriptor)
            _remove_bound_directory(
                root_fd, name, descriptor, state, blobs, owner_id,
            )
        finally:
            os.close(descriptor)
