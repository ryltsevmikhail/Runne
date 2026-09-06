"""Bounded, duplicate-free JSON loading with redacted diagnostics."""
import json
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path

MAX_BYTES = 131072
MAX_DEPTH = 16
MAX_NODES = 8192
MAX_STRING = 4096
MAX_COMPONENTS = 128


def shape_errors(value: object) -> list[str]:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            return ["evidence exceeds structural bounds"]
        if isinstance(item, dict):
            if len(item) * 2 + count + len(pending) > MAX_NODES:
                return ["evidence exceeds structural bounds"]
            if any(not isinstance(key, str) for key in item):
                return ["evidence keys must be strings"]
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif isinstance(item, list):
            if len(item) + count + len(pending) > MAX_NODES:
                return ["evidence exceeds structural bounds"]
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > MAX_STRING:
                return ["evidence string exceeds bounds"]
            if any(token in item.lower() for token in (
                "runne_ci_macos_keychain", "ksecusekeychain", "file://", "/users/", "/private/", "/tmp/",
            )) or re.match(r"^(?:/|~[/\\]|[a-zA-Z]:[/\\])", item):
                return ["evidence contains a forbidden native path or keychain selector"]
        elif item is not None and type(item) not in (bool, int):
            return ["evidence scalar type is invalid"]
        elif type(item) is int and not -(2**63) <= item < 2**63:
            return ["evidence integer exceeds bounds"]
    return []


def _read_regular_file(path: Path) -> bytes:
    """Walk from root/cwd via anchored descriptors; never follow any symlink.

    Every component is checked when opened. A later pathname replacement does
    not redirect an already opened directory or file. Platforms lacking these
    descriptor/no-follow guarantees fail closed instead of pathname fallback.
    """
    components = path.parts[1:] if path.is_absolute() else path.parts
    if path.anchor not in ("", "/") or not components or len(components) > MAX_COMPONENTS or ".." in components:
        raise ValueError("evidence path components are invalid")
    if any(not hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY", "O_CLOEXEC")):
        raise ValueError("safe evidence descriptor opening is unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        with ExitStack() as opened:
            directory = os.open("/" if path.is_absolute() else ".", flags | os.O_DIRECTORY)
            opened.callback(os.close, directory)
            if not stat.S_ISDIR(os.fstat(directory).st_mode):
                raise ValueError("evidence directory descriptor is invalid")
            for component in components[:-1]:
                directory = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
                opened.callback(os.close, directory)
                if not stat.S_ISDIR(os.fstat(directory).st_mode):
                    raise ValueError("evidence directory descriptor is invalid")
            descriptor = os.open(components[-1], flags, dir_fd=directory)
            opened.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("evidence descriptor is not a regular file")
            if info.st_size > MAX_BYTES:
                raise ValueError("evidence exceeds byte limit")
            raw = bytearray()
            while len(raw) <= MAX_BYTES:
                chunk = os.read(descriptor, MAX_BYTES + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            return bytes(raw)
    except (OSError, NotImplementedError):
        raise ValueError("evidence descriptor could not be opened or read safely") from None


def load_json(path: Path) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_value: str) -> None:
        raise ValueError("invalid JSON number")

    raw = _read_regular_file(path)
    if len(raw) > MAX_BYTES:
        raise ValueError("evidence exceeds byte limit")
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("malformed evidence encoding or depth") from error
    if shape_errors(value):
        raise ValueError("evidence shape is invalid")
    return value
