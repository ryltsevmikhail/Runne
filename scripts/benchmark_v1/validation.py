"""Shared fail-closed JSON and scalar validation helpers."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Any


class ContractError(ValueError):
    """A bounded validation failure without input payload disclosure."""


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON constant")


def load_verified_json_with_digest(
    path: pathlib.Path,
    *,
    require_sidecar: bool = True,
) -> tuple[Any, str]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ContractError(f"cannot read artifact: {path.name}") from error
    if len(payload) > 1_048_576:
        raise ContractError(f"artifact too large: {path.name}")
    actual = hashlib.sha256(payload).hexdigest()
    if require_sidecar:
        sidecar = path.with_suffix(path.suffix + ".sha256")
        try:
            fields = sidecar.read_text(encoding="ascii").strip().split("  ")
        except (OSError, UnicodeError) as error:
            raise ContractError(f"missing digest sidecar: {path.name}") from error
        if fields != [actual, path.name]:
            raise ContractError(f"digest mismatch: {path.name}")
    try:
        return (
            json.loads(
                payload,
                object_pairs_hook=_pairs_without_duplicates,
                parse_constant=_reject_constant,
            ),
            actual,
        )
    except ContractError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ContractError(f"malformed JSON: {path.name}") from error


def load_verified_json(path: pathlib.Path, *, require_sidecar: bool = True) -> Any:
    value, _digest = load_verified_json_with_digest(
        path,
        require_sidecar=require_sidecar,
    )
    return value


def object_exact(value: Any, path: str, required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{path}: object required")
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing:
        raise ContractError(f"{path}: missing field {sorted(missing)[0]}")
    if unknown:
        raise ContractError(f"{path}: unknown field")
    return value


def text(
    value: Any,
    path: str,
    *,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 256,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ContractError(f"{path}: bounded string required")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ContractError(f"{path}: invalid format")
    return value


def integer(value: Any, path: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ContractError(f"{path}: bounded integer required")
    return value


def choice(value: Any, path: str, allowed: set[str]) -> str:
    scalar = text(value, path)
    if scalar not in allowed:
        raise ContractError(f"{path}: unsupported value")
    return scalar
