"""Owner-private atomic no-replace publication for evidence directories."""

from __future__ import annotations

import ctypes
import errno
import os
import secrets
import stat
from pathlib import Path
from typing import Callable, Mapping

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_LOCK_CREATE = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_RENAME_NOREPLACE = 1


class AtomicPublishError(ValueError):
    """Atomic no-replace publication was unsafe or unavailable."""


def _load_renameat2():
    if not sys_platform_linux():
        return None
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        return None
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    return function


def sys_platform_linux() -> bool:
    return os.uname().sysname == "Linux"


_RENAMEAT2 = _load_renameat2()


def _open_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise AtomicPublishError("output root must be absolute")
    descriptor = os.open("/", _DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _root_state(fd: int) -> tuple[int, ...]:
    value = os.fstat(fd)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid


def _entry_state(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode


def _canonical_fd_path(fd: int) -> Path:
    try:
        value = os.readlink(f"/proc/self/fd/{fd}")
    except OSError as error:
        raise AtomicPublishError("descriptor path identity is unavailable") from error
    if value.endswith(" (deleted)"):
        raise AtomicPublishError("descriptor path was removed")
    return Path(value)


def _open_root(output_root: Path, checkout_root: Path) -> tuple[int, Path, tuple[int, ...]]:
    descriptor = _open_directory(Path(output_root))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
        ):
            raise AtomicPublishError("evidence output root must be owner-owned mode 0700")
        canonical = _canonical_fd_path(descriptor)
        checkout = Path(checkout_root).resolve(strict=True)
        if canonical == checkout or canonical.is_relative_to(checkout):
            raise AtomicPublishError("evidence output root must be outside the checkout")
        return descriptor, canonical, _root_state(descriptor)
    except Exception:
        os.close(descriptor)
        raise


def _write_all(fd: int, data: bytes) -> None:
    position = 0
    while position < len(data):
        position += os.write(fd, data[position:])


def _create_lock(root_fd: int, name: str) -> tuple[int, tuple[int, ...], bytes]:
    descriptor = os.open(name, _LOCK_CREATE, 0o600, dir_fd=root_fd)
    os.fchmod(descriptor, 0o600)
    token = secrets.token_bytes(32)
    _write_all(descriptor, token)
    os.fsync(descriptor)
    return descriptor, _entry_state(os.fstat(descriptor)), token


def _remove_owned_lock(
    root_fd: int, name: str, descriptor: int, expected_state: tuple[int, ...], token: bytes
) -> None:
    try:
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        os.lseek(descriptor, 0, os.SEEK_SET)
        current_token = os.read(descriptor, len(token) + 1)
        if _entry_state(current) == expected_state and current_token == token:
            os.unlink(name, dir_fd=root_fd)
    except FileNotFoundError:
        pass


def _lock_is_owned(
    root_fd: int, name: str, descriptor: int, expected_state: tuple[int, ...], token: bytes
) -> bool:
    try:
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return _entry_state(current) == expected_state and os.read(descriptor, len(token) + 1) == token
    except FileNotFoundError:
        return False


def _temporary_directory(root_fd: int, source_sha: str) -> tuple[str, int]:
    for _attempt in range(32):
        name = f".{source_sha}.{secrets.token_hex(12)}.tmp"
        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
        except FileExistsError:
            continue
        descriptor = os.open(name, _DIRECTORY, dir_fd=root_fd)
        os.fchmod(descriptor, 0o700)
        return name, descriptor
    raise AtomicPublishError("private temporary directory allocation failed")


def _write_blob(parent_fd: int, name: str, data: bytes) -> tuple[int, ...]:
    descriptor = os.open(name, _FILE_CREATE, 0o600, dir_fd=parent_fd)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        return _entry_state(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def _cleanup_temporary(
    root_fd: int, name: str, temp_fd: int, temp_state: tuple[int, ...],
    owned_files: Mapping[str, tuple[int, ...]],
) -> None:
    try:
        for filename, expected in owned_files.items():
            try:
                current = os.stat(filename, dir_fd=temp_fd, follow_symlinks=False)
                if _entry_state(current) == expected:
                    os.unlink(filename, dir_fd=temp_fd)
            except FileNotFoundError:
                pass
        current_temp = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if _entry_state(current_temp) == temp_state and not os.listdir(temp_fd):
            os.rmdir(name, dir_fd=root_fd)
    except FileNotFoundError:
        pass


def _rename_noreplace(root_fd: int, source: str, destination: str) -> None:
    if _RENAMEAT2 is None:
        raise AtomicPublishError("atomic no-replace directory publication is unsupported")
    result = _RENAMEAT2(
        root_fd, os.fsencode(source), root_fd, os.fsencode(destination), _RENAME_NOREPLACE
    )
    if result == 0:
        return
    failure = ctypes.get_errno()
    if failure in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
        raise AtomicPublishError("atomic no-replace directory publication is unsupported")
    if failure in (errno.EEXIST, errno.ENOTEMPTY):
        raise AtomicPublishError("evidence source directory collision")
    raise AtomicPublishError(f"atomic no-replace publication failed with errno {failure}")


def publish_private_blobs(
    output_root: Path,
    checkout_root: Path,
    source_sha: str,
    blobs: Mapping[str, bytes],
    publication_hook: Callable[[int, str], None] | None = None,
) -> Path:
    root_fd, canonical_root, initial_root_state = _open_root(output_root, checkout_root)
    lock_name = f".{source_sha}.construction-lock"
    lock_fd = temp_fd = -1
    lock_state: tuple[int, ...] | None = None
    lock_token = b""
    temp_name: str | None = None
    temp_state: tuple[int, ...] | None = None
    owned_files: dict[str, tuple[int, ...]] = {}
    published = False
    try:
        lock_fd, lock_state, lock_token = _create_lock(root_fd, lock_name)
        temp_name, temp_fd = _temporary_directory(root_fd, source_sha)
        temp_state = _entry_state(os.fstat(temp_fd))
        for name, data in blobs.items():
            owned_files[name] = _write_blob(temp_fd, name, data)
        os.fsync(temp_fd)
        if publication_hook is not None:
            publication_hook(root_fd, source_sha)
        current_temp = os.stat(temp_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            _entry_state(current_temp) != temp_state
            or not _lock_is_owned(root_fd, lock_name, lock_fd, lock_state, lock_token)
            or _root_state(root_fd) != initial_root_state
        ):
            raise AtomicPublishError("publication parent or source directory identity changed")
        _rename_noreplace(root_fd, temp_name, source_sha)
        published = True
        os.fsync(root_fd)
        if _root_state(root_fd) != initial_root_state:
            raise AtomicPublishError("publication parent identity changed")
        return canonical_root / source_sha
    except (AtomicPublishError, OSError) as error:
        if isinstance(error, AtomicPublishError):
            raise
        raise AtomicPublishError("atomic evidence publication failed") from error
    finally:
        if temp_fd >= 0:
            if not published and temp_name is not None and temp_state is not None:
                _cleanup_temporary(root_fd, temp_name, temp_fd, temp_state, owned_files)
            os.close(temp_fd)
        if lock_fd >= 0 and lock_state is not None:
            _remove_owned_lock(root_fd, lock_name, lock_fd, lock_state, lock_token)
            os.close(lock_fd)
        os.close(root_fd)
