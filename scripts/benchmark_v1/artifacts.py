"""Pinned artifact identity helpers for Benchmark V1."""

from __future__ import annotations

import pathlib
from typing import Any

from .validation import ContractError, load_verified_json_with_digest


SCHEMA_DIGESTS = {
    "journey": "83cdffdef50a4fc05636d14cad35e5ad5774ebd176b1d109aa9858365b12ed8a",
    "outcome": "e383b96f30d9598344ad8a358947a0836c92704c3866e8547dbbc197a1e4bf28",
    "profile": "72294475c5007bf33c3db8bed937990206b047aa155e2a183f70ea1ab0a6a789",
}


def load_trusted_schema(path: pathlib.Path, name: str) -> dict[str, Any]:
    schema, digest = load_verified_json_with_digest(path)
    if digest != SCHEMA_DIGESTS[name]:
        raise ContractError(f"benchmark-{name}: trusted schema digest mismatch")
    if not isinstance(schema, dict):
        raise ContractError(f"benchmark-{name}: object schema required")
    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
    ):
        raise ContractError(f"benchmark-{name}: open schema")
    return schema
