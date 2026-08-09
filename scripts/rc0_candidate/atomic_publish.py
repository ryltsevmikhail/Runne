"""No-replace publication of descriptor-held private evidence blobs."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import secrets
import stat
from pathlib import Path
from typing import Callable, Mapping

from .publish_completion import (
    CompletionPublishError, assert_completed_bound, ensure_completed, open_final,
)
from .publish_fs import (
    DIRECTORY, FILE_CREATE, OWNER_XATTR, PublishFilesystemError,
    assert_lock_bound, entry_state as _entry_state, open_root as _open_root,
    ownership_id, write_all as _write_all,
)
from .publish_recovery import (
    OwnedBlob, RecoveryError, attempt_name, cleanup_held_attempt, recover_attempts,
)

_LOCK_OPEN = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
_RENAME_NOREPLACE = 1


class AtomicPublishError(ValueError):
    """A private construction namespace was unsafe or incomplete."""


def _libc_function(name: str, arguments: tuple[type[ctypes._SimpleCData], ...]):
    if os.uname().sysname != "Linux":
        return None
    try:
        function = getattr(ctypes.CDLL(None, use_errno=True), name)
    except (AttributeError, OSError):
        return None
    function.argtypes = arguments
    function.restype = ctypes.c_int
    return function


_LINKAT = _libc_function(
    "linkat", (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
)
_RENAMEAT2 = _libc_function(
    "renameat2", (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
)


def _invoke(
    hook: Callable[[str, int, str], None] | None, stage: str, root_fd: int, source_sha: str
) -> None:
    if hook is not None:
        hook(stage, root_fd, source_sha)


def _acquire_lock(root, name: str) -> tuple[int, tuple[int, ...], bytes]:
    created = False
    try:
        descriptor = os.open(
            name, _LOCK_OPEN | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root.root_fd
        )
        created = True
    except FileExistsError:
        descriptor = os.open(name, _LOCK_OPEN, dir_fd=root.root_fd)
    try:
        if created:
            os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
        ):
            raise AtomicPublishError("persistent construction lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AtomicPublishError("evidence construction is already active") from error
        expected = _entry_state(os.fstat(descriptor))
        owner_id = ownership_id(root.state, expected)
        assert_lock_bound(root, name, descriptor, expected, owner_id)
        return descriptor, expected, owner_id
    except Exception:
        os.close(descriptor)
        raise


def _write_blob(
    directory_fd: int, name: str, data: bytes,
    owned: dict[str, OwnedBlob],
    hook: Callable[[str, int, str], None] | None, root_fd: int, source_sha: str,
) -> None:
    descriptor = os.open(name, FILE_CREATE, 0o600, dir_fd=directory_fd)
    try:
        owned[name] = OwnedBlob(_entry_state(os.fstat(descriptor)), b"")
        os.fchmod(descriptor, 0o600)
        owned[name] = OwnedBlob(_entry_state(os.fstat(descriptor)), b"")
        _invoke(hook, "after-blob-create", root_fd, source_sha)
        _write_all(descriptor, data)
        owned[name] = OwnedBlob(_entry_state(os.fstat(descriptor)), data)
        _invoke(hook, "after-blob-write", root_fd, source_sha)
        os.fsync(descriptor)
        owned[name] = OwnedBlob(_entry_state(os.fstat(descriptor)), data)
        _invoke(hook, "after-blob-fsync", root_fd, source_sha)
    finally:
        os.close(descriptor)


def _rename_noreplace(root_fd: int, source: str, final: str) -> None:
    if _RENAMEAT2 is None:
        raise AtomicPublishError("atomic no-replace publication is unsupported")
    result = _RENAMEAT2(
        root_fd, os.fsencode(source), root_fd, os.fsencode(final), _RENAME_NOREPLACE
    )
    if result != 0:
        failure = ctypes.get_errno()
        if failure == errno.EEXIST:
            raise AtomicPublishError("evidence final namespace collision")
        raise AtomicPublishError(f"atomic no-replace publication failed with errno {failure}")


def _assert_return_ready(
    root, lock_name: str, lock_fd: int, lock_state: tuple[int, ...], owner_id: bytes,
    final_fd: int, final_state: tuple[int, ...], source_sha: str,
    blobs: Mapping[str, bytes],
) -> None:
    assert_lock_bound(root, lock_name, lock_fd, lock_state, owner_id)
    assert_completed_bound(root, final_fd, final_state, source_sha, blobs, owner_id)
    assert_lock_bound(root, lock_name, lock_fd, lock_state, owner_id)
    assert_completed_bound(root, final_fd, final_state, source_sha, blobs, owner_id)


def publish_private_blobs(
    output_root: Path, checkout_root: Path, source_sha: str, blobs: Mapping[str, bytes],
    publication_hook: Callable[[int, str], None] | None = None,
    boundary_hook: Callable[[str, int, str], None] | None = None,
) -> Path:
    try:
        root = _open_root(Path(output_root), Path(checkout_root))
    except PublishFilesystemError as error:
        raise AtomicPublishError(str(error)) from error
    lock_name = f".{source_sha}.construction-lock"
    lock_fd = staging_fd = final_fd = -1
    staging_state: tuple[int, ...] | None = None
    staging_name = ""
    renamed = completed = False
    owner_id = b""
    owned_blobs: dict[str, OwnedBlob] = {}
    try:
        lock_fd, lock_state, owner_id = _acquire_lock(root, lock_name)
        _invoke(boundary_hook, "after-lock", root.root_fd, source_sha)
        assert_lock_bound(root, lock_name, lock_fd, lock_state, owner_id)
        recover_attempts(root.root_fd, source_sha, owner_id, blobs)
        try:
            os.stat(source_sha, dir_fd=root.root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            assert_lock_bound(root, lock_name, lock_fd, lock_state, owner_id)
            final_fd, final_state = ensure_completed(
                root, source_sha, blobs, owner_id, _LINKAT, None
            )
            completed = True
            _assert_return_ready(
                root, lock_name, lock_fd, lock_state, owner_id, final_fd,
                final_state, source_sha, blobs,
            )
            return root.canonical / source_sha
        staging_name = attempt_name(source_sha, owner_id, secrets.token_hex(16))
        os.mkdir(staging_name, 0o700, dir_fd=root.root_fd)
        staging_state = _entry_state(
            os.stat(staging_name, dir_fd=root.root_fd, follow_symlinks=False)
        )
        _invoke(boundary_hook, "after-staging-mkdir", root.root_fd, source_sha)
        staging_fd = os.open(staging_name, DIRECTORY, dir_fd=root.root_fd)
        if _entry_state(os.fstat(staging_fd)) != staging_state:
            raise AtomicPublishError("staging directory identity changed during open")
        _invoke(boundary_hook, "after-staging-open", root.root_fd, source_sha)
        os.fchmod(staging_fd, 0o700)
        staging_state = _entry_state(os.fstat(staging_fd))
        os.setxattr(staging_fd, OWNER_XATTR, owner_id, flags=os.XATTR_CREATE)
        _invoke(boundary_hook, "after-staging-xattr", root.root_fd, source_sha)
        _invoke(boundary_hook, "after-final-create", root.root_fd, source_sha)
        for name, data in blobs.items():
            _write_blob(
                staging_fd, name, data, owned_blobs, boundary_hook,
                root.root_fd, source_sha,
            )
        os.fsync(staging_fd)
        _invoke(boundary_hook, "after-directory-fsync", root.root_fd, source_sha)
        root.assert_bound()
        _invoke(boundary_hook, "before-staging-rename", root.root_fd, source_sha)
        path = os.stat(staging_name, dir_fd=root.root_fd, follow_symlinks=False)
        if (
            _entry_state(path) != staging_state or _entry_state(os.fstat(staging_fd)) != staging_state
            or os.getxattr(staging_fd, OWNER_XATTR) != owner_id
        ):
            raise AtomicPublishError("staging namespace identity changed")
        assert_lock_bound(root, lock_name, lock_fd, lock_state, owner_id)
        _rename_noreplace(root.root_fd, staging_name, source_sha); renamed = True
        final_fd, final_state = open_final(root.root_fd, source_sha, blobs, owner_id)
        if final_state != staging_state or _entry_state(os.fstat(final_fd)) != staging_state:
            raise AtomicPublishError("published directory is not the held staging directory")
        _invoke(boundary_hook, "after-staging-rename", root.root_fd, source_sha)
        if publication_hook is not None:
            publication_hook(root.root_fd, source_sha)
        _invoke(boundary_hook, "before-marker-publish", root.root_fd, source_sha)
        path = os.stat(source_sha, dir_fd=root.root_fd, follow_symlinks=False)
        if _entry_state(path) != staging_state:
            raise AtomicPublishError("published namespace identity changed")
        assert_lock_bound(root, lock_name, lock_fd, lock_state, owner_id)
        os.close(final_fd); final_fd = -1
        final_fd, final_state = ensure_completed(
            root, source_sha, blobs, owner_id, _LINKAT, boundary_hook
        )
        completed = True
        _invoke(boundary_hook, "after-marker-publish", root.root_fd, source_sha)
        os.fsync(root.root_fd)
        root.assert_bound()
        _invoke(boundary_hook, "after-final-verify", root.root_fd, source_sha)
        _assert_return_ready(
            root, lock_name, lock_fd, lock_state, owner_id, final_fd,
            final_state, source_sha, blobs,
        )
        return root.canonical / source_sha
    except (
        AtomicPublishError, CompletionPublishError, PublishFilesystemError,
        RecoveryError, OSError,
    ) as error:
        if isinstance(error, AtomicPublishError):
            raise
        raise AtomicPublishError("private evidence construction failed") from error
    finally:
        if staging_state is not None and not renamed:
            if staging_fd < 0 and staging_name:
                try:
                    staging_fd = os.open(staging_name, DIRECTORY, dir_fd=root.root_fd)
                except OSError:
                    pass
            if staging_fd >= 0:
                try:
                    cleanup_held_attempt(
                        root.root_fd, staging_fd, staging_state, source_sha, owner_id, blobs,
                        owned_blobs=owned_blobs,
                        allow_unbound_empty=True,
                    )
                except (OSError, RecoveryError):
                    pass
        if renamed and not completed and final_fd >= 0:
            try:
                cleanup_held_attempt(
                    root.root_fd, final_fd, staging_state, source_sha, owner_id, blobs,
                    owned_blobs=owned_blobs,
                )
            except (OSError, RecoveryError):
                pass
        for descriptor in (final_fd, staging_fd, lock_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        root.close()
