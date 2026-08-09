"""Validation of atomically completed private evidence namespaces."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Mapping, Sequence

from .atomic_publish import _entry_state, _manifest, _open_root

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_SHA = re.compile(r"[0-9a-f]{40}")


class CompletionValidationError(ValueError):
    pass


def _full_state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _read_bounded(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining and (chunk := os.read(fd, min(remaining, 1 << 20))):
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
        raise CompletionValidationError("completed evidence blob exceeds its bound")
    return data


def _read_blob(directory_fd: int, name: str) -> bytes:
    descriptor = os.open(name, _FILE, dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
        ):
            raise CompletionValidationError("completed evidence blob mode is unsafe")
        data = _read_bounded(descriptor, 16 << 20)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _full_state(before) != _full_state(os.fstat(descriptor)) or _full_state(before) != _full_state(current):
            raise CompletionValidationError("completed evidence blob identity changed")
        return data
    finally:
        os.close(descriptor)


def load_completed_private_blobs(
    output_root: Path, source_sha: str, expected_names: Sequence[str]
) -> Mapping[str, bytes]:
    if _SHA.fullmatch(source_sha) is None:
        raise CompletionValidationError("completed evidence source SHA is invalid")
    root_fd, _canonical, root_state = _open_root(Path(output_root), None)
    marker_fd = directory_fd = -1
    try:
        marker_name = f".{source_sha}.complete"
        marker_fd = os.open(marker_name, _FILE, dir_fd=root_fd)
        marker_before = os.fstat(marker_fd)
        if (
            not stat.S_ISREG(marker_before.st_mode)
            or stat.S_IMODE(marker_before.st_mode) != 0o600
            or marker_before.st_uid != os.geteuid()
        ):
            raise CompletionValidationError("completion marker mode is unsafe")
        marker = _read_bounded(marker_fd, 64 << 10)
        directory_fd = os.open(source_sha, _DIRECTORY, dir_fd=root_fd)
        directory_state = _entry_state(os.fstat(directory_fd))
        if (
            not stat.S_ISDIR(directory_state[2])
            or stat.S_IMODE(directory_state[2]) != 0o700
            or directory_state[3] != os.geteuid()
        ):
            raise CompletionValidationError("completed evidence directory mode is unsafe")
        if set(os.listdir(directory_fd)) != set(expected_names):
            raise CompletionValidationError("completed evidence does not contain exact blobs")
        blobs = {name: _read_blob(directory_fd, name) for name in expected_names}
        if marker != _manifest(source_sha, directory_state, blobs):
            raise CompletionValidationError("completion marker binding is invalid")
        marker_path = os.stat(marker_name, dir_fd=root_fd, follow_symlinks=False)
        directory_path = os.stat(source_sha, dir_fd=root_fd, follow_symlinks=False)
        if (
            _full_state(marker_before) != _full_state(os.fstat(marker_fd))
            or _full_state(marker_before) != _full_state(marker_path)
            or directory_state != _entry_state(os.fstat(directory_fd))
            or directory_state != _entry_state(directory_path)
            or root_state != _entry_state(os.fstat(root_fd))
        ):
            raise CompletionValidationError("completed evidence namespace changed")
        return blobs
    except CompletionValidationError:
        raise
    except OSError as error:
        raise CompletionValidationError("completed evidence namespace is unavailable") from error
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        if marker_fd >= 0:
            os.close(marker_fd)
        os.close(root_fd)
