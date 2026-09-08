"""Bounded canonical JSON and descriptor-only evidence loading."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path


class Rejected(ValueError):
    """A redacted failure; callers never serialize rejected input values."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def load_json(path: Path) -> object:
    """Open a regular JSON file component-by-component without following links."""
    descriptor = _open_regular(path)
    try:
        return parse_json(_read_bounded(descriptor))
    finally:
        os.close(descriptor)


def load_installed_json(path: Path) -> object:
    """Parse a root-owned immutable policy from its admitted descriptor."""
    descriptor = _open_regular(path)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise Rejected("protected policy permissions are invalid")
        return parse_json(_read_bounded(descriptor))
    finally:
        os.close(descriptor)


def read_file(path: Path, limit: int = 16 * 1024 * 1024) -> bytes:
    descriptor = _open_regular(path)
    try:
        return _read_bounded(descriptor, limit)
    finally:
        os.close(descriptor)


def entries(path: Path) -> set[str]:
    descriptor = _open_path(path, final_directory=True)
    try:
        return set(os.listdir(descriptor))
    except OSError:
        raise Rejected("evidence directory is unavailable") from None
    finally:
        os.close(descriptor)


def file_digest(path: Path) -> str:
    descriptor = _open_regular(path)
    try:
        digest = hashlib.sha256()
        while block := os.read(descriptor, 65536): digest.update(block)
        return digest.hexdigest()
    except OSError:
        raise Rejected("evidence file is unavailable") from None
    finally:
        os.close(descriptor)


def inventory(path: Path) -> set[str]:
    descriptor = _open_path(path, final_directory=True)
    try: return _inventory(descriptor, "")
    finally: os.close(descriptor)


def package_snapshot(path: Path) -> dict[str, str]:
    """Hash one root-owned immutable package tree through retained descriptors."""
    descriptor = _open_path(path, final_directory=True)
    try: return _snapshot(descriptor, "")
    finally: os.close(descriptor)


def _snapshot(descriptor: int, prefix: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for name in os.listdir(descriptor):
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH): raise Rejected("package component is mutable")
            relative = f"{prefix}/{name}" if prefix else name
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try: result.update(_snapshot(child, relative))
                finally: os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1: raise Rejected("package hardlink is not admitted")
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    hashed = hashlib.sha256()
                    while block := os.read(child, 65536): hashed.update(block)
                    result[relative] = hashed.hexdigest()
                finally: os.close(child)
            else: raise Rejected("package inventory is invalid")
        return result
    except OSError: raise Rejected("package inventory is unavailable") from None


def _inventory(descriptor: int, prefix: str) -> set[str]:
    result: set[str] = set()
    try:
        for name in os.listdir(descriptor):
            if name in {".", ".."} or "/" in name: raise Rejected("package inventory is invalid")
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            relative = f"{prefix}/{name}" if prefix else name
            if stat.S_ISREG(info.st_mode): result.add(relative); continue
            if not stat.S_ISDIR(info.st_mode): raise Rejected("package inventory is invalid")
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            try: result.update(_inventory(child, relative))
            finally: os.close(child)
        return result
    except OSError:
        raise Rejected("package inventory is unavailable") from None


def _open_regular(path: Path) -> int:
    return _open_path(path, final_directory=False)


def _open_path(path: Path, final_directory: bool) -> int:
    current: int | None = None
    try:
        raw = os.fspath(path)
        parts = Path(raw).parts[1:] if os.path.isabs(raw) else ()
        if not parts or len(parts) > 128 or any(part in {"", ".", ".."} for part in parts):
            raise Rejected("evidence path is invalid")
        nofollow, directory = getattr(os, "O_NOFOLLOW", None), getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise Rejected("platform lacks no-follow descriptor support")
        current = os.open("/", os.O_RDONLY | directory)
        for index, part in enumerate(parts):
            last = index + 1 == len(parts)
            flags = os.O_RDONLY | nofollow
            flags |= directory if not last or final_directory else getattr(os, "O_NONBLOCK", 0)
            following = os.open(part, flags, dir_fd=current)
            os.close(current); current = following
        info = os.fstat(current)
        if not (stat.S_ISDIR(info.st_mode) if final_directory else stat.S_ISREG(info.st_mode)):
            raise Rejected("evidence descriptor has an invalid file type")
        return current
    except (OSError, Rejected):
        if current is not None:
            try: os.close(current)
            except OSError: pass
        raise Rejected("evidence path is unavailable or not admitted") from None


def _read_bounded(descriptor: int, limit: int = 131072) -> bytes:
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 0 or info.st_size > limit:
            raise Rejected("evidence file is not an admitted regular file")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65536))
            if not block: raise Rejected("evidence file changed while reading")
            chunks.append(block); remaining -= len(block)
        if os.read(descriptor, 1): raise Rejected("evidence file changed while reading")
        return b"".join(chunks)
    except OSError:
        raise Rejected("evidence file is unavailable") from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("evidence JSON is absent or malformed")
        result[key] = value
    return result


def _reject_constant(_: str) -> object:
    raise Rejected("evidence JSON is absent or malformed")


def _reject_float(_: str) -> object:
    raise Rejected("evidence JSON is absent or malformed")


def parse_json(raw: bytes | str) -> object:
    """Decode one bounded canonical JSON value from an already-bounded source."""
    try:
        source = raw.decode("ascii") if isinstance(raw, bytes) else raw
        value = json.loads(source, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant, parse_float=_reject_float)
        _bounded(value)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, Rejected):
        raise Rejected("evidence JSON is absent or malformed") from None


def _bounded(value: object, depth: int = 0, counter: list[int] | None = None) -> None:
    if depth > 16:
        raise Rejected("evidence JSON exceeds resource bounds")
    counter = [0] if counter is None else counter
    counter[0] += 1
    if counter[0] > 8192:
        raise Rejected("evidence JSON exceeds resource bounds")
    if isinstance(value, str):
        if len(value) > 4096:
            raise Rejected("evidence JSON exceeds resource bounds")
    elif isinstance(value, dict):
        for key, item in value.items():
            _bounded(key, depth + 1, counter)
            _bounded(item, depth + 1, counter)
    elif isinstance(value, list):
        for item in value:
            _bounded(item, depth + 1, counter)
