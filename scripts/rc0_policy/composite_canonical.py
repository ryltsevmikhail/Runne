"""Bounded canonical JSON codec for internal adjunct composite graphs."""

from __future__ import annotations

import json
from typing import Any

from scripts.rc0_policy.canonical import (
    StrictJSONError,
    _check,
    _integer,
    _pairs,
    _reject_number,
)


MAX_COMPOSITE_DOCUMENT_BYTES = 262_144


def _encode(value: Any) -> bytes:
    _check(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise StrictJSONError(str(error)) from error
    if len(encoded) > MAX_COMPOSITE_DOCUMENT_BYTES:
        raise StrictJSONError(
            f"canonical document exceeds {MAX_COMPOSITE_DOCUMENT_BYTES} bytes"
        )
    return encoded


def canonical_composite_bytes(value: Any) -> bytes:
    """Encode a bounded internal composite with the baseline canonical ABI."""
    return _encode(value)


def loads_composite_canonical(raw: bytes) -> Any:
    """Parse one byte-canonical internal composite, never an external envelope."""
    if not isinstance(raw, bytes):
        raise TypeError("raw fixture input must be bytes")
    if len(raw) > MAX_COMPOSITE_DOCUMENT_BYTES:
        raise StrictJSONError(
            f"document exceeds {MAX_COMPOSITE_DOCUMENT_BYTES} bytes"
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise StrictJSONError("UTF-8 BOM is forbidden")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
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
    if _encode(value) != raw:
        raise StrictJSONError("composite document is not canonical")
    return value
