"""Bounded, duplicate-free JSON loading with redacted diagnostics."""
import json
import re
from pathlib import Path

MAX_BYTES = 131072
MAX_DEPTH = 16
MAX_NODES = 8192
MAX_STRING = 4096


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

    if path.is_symlink() or not path.is_file():
        raise ValueError("evidence must be a regular nonsymlink file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("evidence exceeds byte limit")
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("malformed evidence encoding or depth") from error
    if shape_errors(value):
        raise ValueError("evidence shape is invalid")
    return value
