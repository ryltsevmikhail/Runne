"""Crash-safe persistent construction-lock creation and acquisition."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import stat
from typing import Callable

from .publish_fs import RootHandle, assert_lock_bound, entry_state, ownership_id

AT_EMPTY_PATH = 0x1000
_LOCK_OPEN = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK


class LockPublishError(ValueError):
    pass


def _lock_state(descriptor: int) -> tuple[int, ...]:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
    ):
        raise LockPublishError("persistent construction lock is unsafe")
    return entry_state(metadata)


def _invoke(
    hook: Callable[[str, int, str], None] | None,
    stage: str,
    root_fd: int,
    source_sha: str,
) -> None:
    if hook is not None:
        hook(stage, root_fd, source_sha)


def _open_new_lock(
    root: RootHandle,
    name: str,
    linkat,
    hook: Callable[[str, int, str], None] | None,
    source_sha: str,
) -> int:
    if linkat is None or not hasattr(os, "O_TMPFILE"):
        raise LockPublishError("atomic persistent construction lock is unsupported")
    try:
        descriptor = os.open(
            ".", os.O_RDWR | os.O_TMPFILE | os.O_NOFOLLOW, 0o600,
            dir_fd=root.root_fd,
        )
    except OSError as error:
        raise LockPublishError(
            "atomic persistent construction lock is unsupported"
        ) from error
    try:
        _invoke(hook, "after-lock-tmpfile-open", root.root_fd, source_sha)
        os.fchmod(descriptor, 0o600)
        _invoke(hook, "after-lock-fchmod", root.root_fd, source_sha)
        os.fsync(descriptor)
        _invoke(hook, "after-lock-fsync", root.root_fd, source_sha)
        _lock_state(descriptor)
        root.assert_bound()
        result = linkat(
            descriptor, b"", root.root_fd, os.fsencode(name), AT_EMPTY_PATH
        )
        if result != 0:
            failure = ctypes.get_errno()
            if failure == errno.EEXIST:
                os.close(descriptor)
                descriptor = -1
                return os.open(name, _LOCK_OPEN, dir_fd=root.root_fd)
            raise LockPublishError(
                f"atomic persistent construction lock failed with errno {failure}"
            )
        _invoke(hook, "after-lock-link", root.root_fd, source_sha)
        os.fsync(root.root_fd)
        _invoke(hook, "after-lock-root-fsync", root.root_fd, source_sha)
        return descriptor
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def acquire_persistent_lock(
    root: RootHandle,
    name: str,
    linkat,
    hook: Callable[[str, int, str], None] | None,
    source_sha: str,
) -> tuple[int, tuple[int, ...], bytes]:
    try:
        descriptor = os.open(name, _LOCK_OPEN, dir_fd=root.root_fd)
    except FileNotFoundError:
        descriptor = _open_new_lock(root, name, linkat, hook, source_sha)
    try:
        _lock_state(descriptor)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise LockPublishError("evidence construction is already active") from error
        state = _lock_state(descriptor)
        owner_id = ownership_id(root.state, state)
        assert_lock_bound(root, name, descriptor, state, owner_id)
        return descriptor, state, owner_id
    except Exception:
        os.close(descriptor)
        raise
