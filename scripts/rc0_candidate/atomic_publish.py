"""Descriptor-held evidence construction with an atomic completion authority."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import os
import secrets
import stat
from pathlib import Path
from typing import Callable, Mapping

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_LOCK_OPEN = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
_AT_EMPTY_PATH = 0x1000
_OWNER_XATTR = "user.gocode.rc0-construction-owner"


class AtomicPublishError(ValueError):
    """A private construction namespace was unsafe or incomplete."""


def _load_linkat():
    if os.uname().sysname != "Linux" or not hasattr(os, "O_TMPFILE"):
        return None
    try:
        function = ctypes.CDLL(None, use_errno=True).linkat
    except (AttributeError, OSError):
        return None
    function.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
    )
    function.restype = ctypes.c_int
    return function


_LINKAT = _load_linkat()


def _open_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise AtomicPublishError("output root must be canonical absolute")
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


def _entry_state(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid


def _canonical_fd_path(fd: int) -> Path:
    try:
        value = os.readlink(f"/proc/self/fd/{fd}")
    except OSError as error:
        raise AtomicPublishError("descriptor path identity is unavailable") from error
    if value.endswith(" (deleted)"):
        raise AtomicPublishError("descriptor path was removed")
    return Path(value)


def _open_root(output_root: Path, checkout_root: Path | None) -> tuple[int, Path, tuple[int, ...]]:
    descriptor = _open_directory(Path(output_root))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
        ):
            raise AtomicPublishError("evidence output root must be owner-owned mode 0700")
        canonical = _canonical_fd_path(descriptor)
        if checkout_root is not None:
            checkout = Path(checkout_root).resolve(strict=True)
            if canonical == checkout or canonical.is_relative_to(checkout):
                raise AtomicPublishError("evidence output root must be outside the checkout")
        return descriptor, canonical, _entry_state(metadata)
    except Exception:
        os.close(descriptor)
        raise


def _write_all(fd: int, data: bytes) -> None:
    position = 0
    while position < len(data):
        written = os.write(fd, data[position:])
        if written <= 0:
            raise OSError(errno.EIO, "short evidence write")
        position += written


def _lock_matches(root_fd: int, name: str, fd: int, expected: tuple[int, ...]) -> bool:
    try:
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return _entry_state(current) == expected == _entry_state(os.fstat(fd))


def _acquire_lock(root_fd: int, name: str) -> tuple[int, tuple[int, ...], bytes]:
    created = False
    try:
        descriptor = os.open(name, _LOCK_OPEN | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root_fd)
        created = True
    except FileExistsError:
        descriptor = os.open(name, _LOCK_OPEN, dir_fd=root_fd)
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
        token = secrets.token_hex(32).encode("ascii") + b"\n"
        os.ftruncate(descriptor, 0)
        _write_all(descriptor, token)
        os.fsync(descriptor)
        expected = _entry_state(os.fstat(descriptor))
        if not _lock_matches(root_fd, name, descriptor, expected):
            raise AtomicPublishError("persistent construction lock identity changed")
        return descriptor, expected, token
    except Exception:
        os.close(descriptor)
        raise


def _invoke(
    hook: Callable[[str, int, str], None] | None, stage: str, root_fd: int, source_sha: str
) -> None:
    if hook is not None:
        hook(stage, root_fd, source_sha)


def _write_blob(
    parent_fd: int, name: str, data: bytes, owned: dict[str, tuple[int, ...]],
    hook: Callable[[str, int, str], None] | None, root_fd: int, source_sha: str,
) -> None:
    descriptor = os.open(name, _FILE_CREATE, 0o600, dir_fd=parent_fd)
    owned[name] = _entry_state(os.fstat(descriptor))
    try:
        os.fchmod(descriptor, 0o600)
        _invoke(hook, "after-blob-create", root_fd, source_sha)
        _write_all(descriptor, data)
        _invoke(hook, "after-blob-write", root_fd, source_sha)
        os.fsync(descriptor)
        _invoke(hook, "after-blob-fsync", root_fd, source_sha)
        owned[name] = _entry_state(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def _manifest(source_sha: str, directory: tuple[int, ...], blobs: Mapping[str, bytes]) -> bytes:
    lines = [
        "GOCODE_RC0_COMPLETE_V1", f"source_sha={source_sha}",
        f"directory_dev={directory[0]}", f"directory_ino={directory[1]}",
    ]
    for name in sorted(blobs, key=lambda value: value.encode("ascii")):
        lines.append(f"{hashlib.sha256(blobs[name]).hexdigest()} {len(blobs[name])} {name}")
    return ("\n".join(lines) + "\n").encode("ascii")


def _publish_marker(root_fd: int, name: str, data: bytes) -> tuple[int, ...]:
    if _LINKAT is None:
        raise AtomicPublishError("atomic completion publication is unsupported")
    try:
        descriptor = os.open(".", os.O_RDWR | os.O_TMPFILE, 0o600, dir_fd=root_fd)
    except OSError as error:
        raise AtomicPublishError("atomic completion publication is unsupported") from error
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        expected = _entry_state(os.fstat(descriptor))
        result = _LINKAT(descriptor, b"", root_fd, os.fsencode(name), _AT_EMPTY_PATH)
        if result != 0:
            failure = ctypes.get_errno()
            if failure == errno.EEXIST:
                raise AtomicPublishError("evidence completion marker collision")
            raise AtomicPublishError(f"atomic completion publication failed with errno {failure}")
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if _entry_state(current) != expected:
            raise AtomicPublishError("completion marker identity changed")
        return expected
    finally:
        os.close(descriptor)


def _cleanup_incomplete(
    root_fd: int, name: str, directory_fd: int, directory_state: tuple[int, ...],
    owned: Mapping[str, tuple[int, ...]], owner_token: bytes, owner_bound: bool,
) -> None:
    if owner_bound:
        try:
            if os.getxattr(directory_fd, _OWNER_XATTR) != owner_token:
                return
        except OSError:
            return
    for filename, expected in owned.items():
        try:
            current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            if _entry_state(current) == expected:
                os.unlink(filename, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
    try:
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if _entry_state(current) == directory_state and not os.listdir(directory_fd):
            os.rmdir(name, dir_fd=root_fd)
    except FileNotFoundError:
        pass


def publish_private_blobs(
    output_root: Path,
    checkout_root: Path,
    source_sha: str,
    blobs: Mapping[str, bytes],
    publication_hook: Callable[[int, str], None] | None = None,
    boundary_hook: Callable[[str, int, str], None] | None = None,
) -> Path:
    root_fd, canonical_root, root_state = _open_root(output_root, checkout_root)
    lock_name = f".{source_sha}.construction-lock"
    marker_name = f".{source_sha}.complete"
    lock_fd = directory_fd = -1
    directory_state: tuple[int, ...] | None = None
    lock_state: tuple[int, ...] | None = None
    lock_token = b""
    owner_bound = False
    owned: dict[str, tuple[int, ...]] = {}
    published = False
    try:
        lock_fd, lock_state, lock_token = _acquire_lock(root_fd, lock_name)
        _invoke(boundary_hook, "after-lock", root_fd, source_sha)
        os.mkdir(source_sha, 0o700, dir_fd=root_fd)
        directory_fd = os.open(source_sha, _DIRECTORY, dir_fd=root_fd)
        directory_state = _entry_state(os.fstat(directory_fd))
        os.fchmod(directory_fd, 0o700)
        directory_state = _entry_state(os.fstat(directory_fd))
        os.setxattr(directory_fd, _OWNER_XATTR, lock_token, flags=os.XATTR_CREATE)
        owner_bound = True
        _invoke(boundary_hook, "after-final-create", root_fd, source_sha)
        for name, data in blobs.items():
            _write_blob(
                directory_fd, name, data, owned, boundary_hook, root_fd, source_sha
            )
        os.fsync(directory_fd)
        _invoke(boundary_hook, "after-directory-fsync", root_fd, source_sha)
        if publication_hook is not None:
            publication_hook(root_fd, source_sha)
        _invoke(boundary_hook, "before-marker-publish", root_fd, source_sha)
        current = os.stat(source_sha, dir_fd=root_fd, follow_symlinks=False)
        if (
            _entry_state(current) != directory_state
            or root_state != _entry_state(os.fstat(root_fd))
            or not _lock_matches(root_fd, lock_name, lock_fd, lock_state)
        ):
            raise AtomicPublishError("construction namespace identity changed")
        _publish_marker(root_fd, marker_name, _manifest(source_sha, directory_state, blobs))
        published = True
        _invoke(boundary_hook, "after-marker-publish", root_fd, source_sha)
        os.fsync(root_fd)
        return canonical_root / source_sha
    except (AtomicPublishError, OSError) as error:
        if isinstance(error, AtomicPublishError):
            raise
        raise AtomicPublishError("private evidence construction failed") from error
    finally:
        if directory_fd >= 0 and not published and directory_state is not None:
            try:
                _cleanup_incomplete(
                    root_fd, source_sha, directory_fd, directory_state, owned,
                    lock_token, owner_bound,
                )
            except OSError:
                pass
        for descriptor in (directory_fd, lock_fd, root_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
