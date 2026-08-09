"""Completion-marker creation and binding for an atomically renamed directory."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import stat
from typing import Callable, Mapping

from .publish_fs import (
    DIRECTORY, FILE, OWNER_XATTR, RootHandle, entry_state, full_state,
    read_bounded, write_all,
)
from .publish_recovery import validate_blob_set

AT_EMPTY_PATH = 0x1000


class CompletionPublishError(ValueError):
    pass


def manifest(
    source_sha: str, directory: tuple[int, ...], blobs: Mapping[str, bytes], token: bytes
) -> bytes:
    lines = [
        "GOCODE_RC0_COMPLETE_V2", f"source_sha={source_sha}",
        f"owner_token={token.decode('ascii')}", f"directory_dev={directory[0]}",
        f"directory_ino={directory[1]}",
    ]
    for name in sorted(blobs, key=lambda value: value.encode("ascii")):
        lines.append(f"{hashlib.sha256(blobs[name]).hexdigest()} {len(blobs[name])} {name}")
    return ("\n".join(lines) + "\n").encode("ascii")


def marker_matches(
    root_fd: int, marker_name: str, source_sha: str, state: tuple[int, ...],
    blobs: Mapping[str, bytes], token: bytes,
) -> bool:
    descriptor = os.open(marker_name, FILE, dir_fd=root_fd)
    try:
        before = os.fstat(descriptor)
        if os.getxattr(descriptor, OWNER_XATTR) != token:
            raise CompletionPublishError("completion marker owner changed")
        data = read_bounded(descriptor, 64 << 10)
        path = os.stat(marker_name, dir_fd=root_fd, follow_symlinks=False)
        return (
            stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_uid == os.geteuid()
            and full_state(before) == full_state(os.fstat(descriptor))
            and full_state(before) == full_state(path)
            and data == manifest(source_sha, state, blobs, token)
        )
    finally:
        os.close(descriptor)


def publish_marker(
    root_fd: int, marker_name: str, data: bytes, token: bytes, linkat,
    hook: Callable[[str, int, str], None] | None, source_sha: str,
) -> None:
    if linkat is None or not hasattr(os, "O_TMPFILE"):
        raise CompletionPublishError("atomic completion publication is unsupported")
    try:
        descriptor = os.open(".", os.O_RDWR | os.O_TMPFILE, 0o600, dir_fd=root_fd)
    except OSError as error:
        raise CompletionPublishError("atomic completion publication is unsupported") from error
    try:
        os.fchmod(descriptor, 0o600)
        os.setxattr(descriptor, OWNER_XATTR, token, flags=os.XATTR_CREATE)
        write_all(descriptor, data); os.fsync(descriptor)
        result = linkat(descriptor, b"", root_fd, os.fsencode(marker_name), AT_EMPTY_PATH)
        if result != 0:
            failure = ctypes.get_errno()
            if failure == errno.EEXIST:
                raise CompletionPublishError("evidence completion marker collision")
            raise CompletionPublishError(
                f"atomic completion publication failed with errno {failure}"
            )
        expected = full_state(os.fstat(descriptor))
        if hook is not None:
            hook("after-marker-link", root_fd, source_sha)
        current = os.stat(marker_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            full_state(current) != expected
            or full_state(os.fstat(descriptor)) != expected
        ):
            raise CompletionPublishError("completion marker identity changed")
    finally:
        os.close(descriptor)


def open_final(
    root_fd: int, source_sha: str, blobs: Mapping[str, bytes], token: bytes
) -> tuple[int, tuple[int, ...]]:
    descriptor = os.open(source_sha, DIRECTORY, dir_fd=root_fd)
    try:
        metadata = os.fstat(descriptor)
        state = entry_state(metadata)
        if (
            not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid() or os.getxattr(descriptor, OWNER_XATTR) != token
        ):
            raise CompletionPublishError("final evidence namespace is not owned")
        validate_blob_set(descriptor, blobs, exact=True)
        path = os.stat(source_sha, dir_fd=root_fd, follow_symlinks=False)
        if (
            full_state(path) != full_state(metadata)
            or full_state(os.fstat(descriptor)) != full_state(metadata)
            or set(os.listdir(descriptor)) != set(blobs)
        ):
            raise CompletionPublishError("final evidence namespace identity changed")
        return descriptor, state
    except Exception:
        os.close(descriptor)
        raise


def ensure_completed(
    root: RootHandle, source_sha: str, blobs: Mapping[str, bytes], token: bytes,
    linkat, hook: Callable[[str, int, str], None] | None,
) -> tuple[int, tuple[int, ...]]:
    directory_fd, state = open_final(root.root_fd, source_sha, blobs, token)
    marker_name = f".{source_sha}.complete"
    try:
        try:
            valid = marker_matches(root.root_fd, marker_name, source_sha, state, blobs, token)
        except FileNotFoundError:
            publish_marker(
                root.root_fd, marker_name, manifest(source_sha, state, blobs, token),
                token, linkat, hook, source_sha,
            )
            valid = marker_matches(root.root_fd, marker_name, source_sha, state, blobs, token)
        if not valid:
            raise CompletionPublishError("completion marker binding is invalid")
        root.assert_bound()
        return directory_fd, state
    except Exception:
        os.close(directory_fd)
        raise
