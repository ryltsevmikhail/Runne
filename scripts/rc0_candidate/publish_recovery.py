"""Authenticated staging-name recovery for interrupted evidence construction."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from typing import Mapping

from .publish_fs import DIRECTORY, OWNER_XATTR, entry_state, read_regular

_ATTEMPT = re.compile(
    r"\.([0-9a-f]{40})\.([0-9a-f]{32})\.([0-9a-f]{64})\.attempt"
)


class RecoveryError(ValueError):
    pass


def attempt_name(source_sha: str, token: bytes, nonce: str) -> str:
    message = source_sha.encode("ascii") + b"\0" + nonce.encode("ascii")
    tag = hmac.new(token, message, hashlib.sha256).hexdigest()
    return f".{source_sha}.{nonce}.{tag}.attempt"


def authenticated_attempt(name: str, source_sha: str, token: bytes) -> bool:
    match = _ATTEMPT.fullmatch(name)
    if match is None or match.group(1) != source_sha:
        return False
    expected = attempt_name(source_sha, token, match.group(2))
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


def _remove_bound_directory(
    root_fd: int, name: str, directory_fd: int, state: tuple[int, ...],
    blobs: Mapping[str, bytes], token: bytes, *, allow_unbound_empty: bool = False,
) -> None:
    _directory_safe(directory_fd)
    try:
        owner = os.getxattr(directory_fd, OWNER_XATTR)
    except OSError:
        owner = None
    if owner != token:
        if not allow_unbound_empty or owner is not None or os.listdir(directory_fd):
            raise RecoveryError("construction directory is not owned by this root token")
    names = set(os.listdir(directory_fd))
    if not names.issubset(blobs):
        raise RecoveryError("owned construction directory has foreign entries")
    states: dict[str, tuple[int, ...]] = {}
    for filename in names:
        _data, states[filename] = read_regular(directory_fd, filename)
    for filename, expected in states.items():
        current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        if entry_state(current) != expected:
            raise RecoveryError("owned construction blob changed during cleanup")
        os.unlink(filename, dir_fd=directory_fd)
    current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    if entry_state(current) != state or os.listdir(directory_fd):
        raise RecoveryError("owned construction directory changed during cleanup")
    os.rmdir(name, dir_fd=root_fd)


def cleanup_held_attempt(
    root_fd: int, directory_fd: int, state: tuple[int, ...], source_sha: str,
    token: bytes, blobs: Mapping[str, bytes], *, allow_unbound_empty: bool = False,
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
        root_fd, matches[0], directory_fd, state, blobs, token,
        allow_unbound_empty=allow_unbound_empty,
    )


def recover_attempts(
    root_fd: int, source_sha: str, token: bytes, blobs: Mapping[str, bytes]
) -> None:
    suffix = ".attempt"
    prefix = f".{source_sha}."
    for name in tuple(os.listdir(root_fd)):
        if not name.startswith(prefix) or not name.endswith(suffix):
            continue
        if not authenticated_attempt(name, source_sha, token):
            raise RecoveryError("foreign construction attempt blocks recovery")
        descriptor = os.open(name, DIRECTORY, dir_fd=root_fd)
        try:
            state = _directory_safe(descriptor)
            try:
                owner = os.getxattr(descriptor, OWNER_XATTR)
            except OSError:
                owner = None
            _remove_bound_directory(
                root_fd, name, descriptor, state, blobs, token,
                allow_unbound_empty=owner is None,
            )
        finally:
            os.close(descriptor)
