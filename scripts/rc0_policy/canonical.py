"""Bounded canonical JSON primitives for local fixtures only."""

from __future__ import annotations

import json
import unicodedata
from typing import Any

MAX_DOCUMENT_BYTES = 65_536
MAX_DEPTH = 32
MAX_CONTAINER_ITEMS = 4_096
MAX_STRING_BYTES = 4_096
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**64 - 1


class StrictJSONError(ValueError):
    """Input is outside the closed RC0 fixture JSON profile."""


def _integer(token: str) -> int:
    if token == "-0":
        raise StrictJSONError("negative zero is not canonical")
    value = int(token)
    if not MIN_INTEGER <= value <= MAX_INTEGER:
        raise StrictJSONError("integer is outside the bounded exact range")
    return value


def _reject_number(token: str) -> None:
    raise StrictJSONError(f"non-integer or non-finite number is forbidden: {token}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def _check(value: Any, depth: int = 1) -> None:
    if depth > MAX_DEPTH:
        raise StrictJSONError(f"JSON depth exceeds {MAX_DEPTH}")
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value:
            raise StrictJSONError("strings and object keys must be NFC")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise StrictJSONError("string contains invalid Unicode") from error
        if len(encoded) > MAX_STRING_BYTES:
            raise StrictJSONError(f"string exceeds {MAX_STRING_BYTES} UTF-8 bytes")
    elif type(value) is dict:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise StrictJSONError(f"object exceeds {MAX_CONTAINER_ITEMS} members")
        for key, item in value.items():
            if type(key) is not str:
                raise StrictJSONError("object keys must be strings")
            _check(key, depth + 1)
            _check(item, depth + 1)
    elif type(value) is list:
        if len(value) > MAX_CONTAINER_ITEMS:
            raise StrictJSONError(f"array exceeds {MAX_CONTAINER_ITEMS} items")
        for item in value:
            _check(item, depth + 1)
    elif type(value) is int:
        if not MIN_INTEGER <= value <= MAX_INTEGER:
            raise StrictJSONError("integer is outside the bounded exact range")
    elif value is not None and type(value) is not bool:
        raise StrictJSONError(f"unsupported JSON value type: {type(value).__name__}")


def loads_canonical(raw: bytes) -> Any:
    """Parse strict UTF-8 JSON and enforce all fixture resource limits."""
    if not isinstance(raw, bytes):
        raise TypeError("raw fixture input must be bytes")
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise StrictJSONError(f"document exceeds {MAX_DOCUMENT_BYTES} bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise StrictJSONError("UTF-8 BOM is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except StrictJSONError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StrictJSONError(str(error)) from error
    _check(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    """Return deterministic NFC UTF-8 JSON with keys sorted by Unicode value."""
    _check(value)
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise StrictJSONError(str(error)) from error
