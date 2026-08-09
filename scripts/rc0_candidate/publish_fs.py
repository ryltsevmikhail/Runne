"""Descriptor and pathname identity helpers for private evidence publication."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
FILE_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
OWNER_XATTR = "user.gocode.rc0-construction-owner"


class PublishFilesystemError(ValueError):
    pass


def entry_state(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid


def full_state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def write_all(fd: int, data: bytes) -> None:
    position = 0
    while position < len(data):
        written = os.write(fd, data[position:])
        if written <= 0:
            raise OSError(errno.EIO, "short evidence write")
        position += written


def read_bounded(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining and (chunk := os.read(fd, min(remaining, 1 << 20))):
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
        raise PublishFilesystemError("evidence entry exceeds its bound")
    return data


def read_regular(parent_fd: int, name: str, limit: int = 16 << 20) -> tuple[bytes, tuple[int, ...]]:
    descriptor = os.open(name, FILE, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
        ):
            raise PublishFilesystemError("evidence entry mode is unsafe")
        data = read_bounded(descriptor, limit)
        path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if full_state(before) != full_state(os.fstat(descriptor)) or full_state(before) != full_state(path):
            raise PublishFilesystemError("evidence entry identity changed")
        return data, entry_state(before)
    finally:
        os.close(descriptor)


@dataclass
class RootHandle:
    parent_fd: int
    root_fd: int
    basename: str
    canonical: Path
    state: tuple[int, ...]

    def assert_bound(self) -> None:
        current = os.stat(self.basename, dir_fd=self.parent_fd, follow_symlinks=False)
        held = os.fstat(self.root_fd)
        if (
            self.state != entry_state(current)
            or self.state != entry_state(held)
            or _canonical_fd_path(self.root_fd) != self.canonical
        ):
            raise PublishFilesystemError("configured evidence output root changed")
        if (
            not stat.S_ISDIR(held.st_mode)
            or stat.S_IMODE(held.st_mode) != 0o700
            or held.st_uid != os.geteuid()
        ):
            raise PublishFilesystemError("evidence output root is unsafe")

    def close(self) -> None:
        os.close(self.root_fd)
        os.close(self.parent_fd)


def _canonical_fd_path(fd: int) -> Path:
    try:
        value = os.readlink(f"/proc/self/fd/{fd}")
    except OSError as error:
        raise PublishFilesystemError("descriptor path identity is unavailable") from error
    if value.endswith(" (deleted)"):
        raise PublishFilesystemError("descriptor path was removed")
    return Path(value)


def open_root(output_root: Path, checkout_root: Path | None) -> RootHandle:
    path = Path(output_root)
    if not path.is_absolute() or len(path.parts) < 2 or any(
        part in (".", "..") for part in path.parts
    ):
        raise PublishFilesystemError("output root must be canonical absolute")
    parent = os.open("/", DIRECTORY)
    root = -1
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        root = os.open(path.name, DIRECTORY, dir_fd=parent)
        metadata = os.fstat(root)
        canonical = _canonical_fd_path(root)
        handle = RootHandle(parent, root, path.name, canonical, entry_state(metadata))
        handle.assert_bound()
        if checkout_root is not None:
            checkout = Path(checkout_root).resolve(strict=True)
            if canonical == checkout or canonical.is_relative_to(checkout):
                raise PublishFilesystemError("evidence output root must be outside the checkout")
        return handle
    except Exception:
        if root >= 0:
            os.close(root)
        os.close(parent)
        raise
