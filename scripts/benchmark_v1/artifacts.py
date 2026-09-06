"""Pinned artifact identity helpers for Benchmark V1."""

from __future__ import annotations

import hashlib
import pathlib
from typing import Any

from .validation import ContractError, load_verified_json


SCHEMA_DIGESTS = {
    "journey": "83cdffdef50a4fc05636d14cad35e5ad5774ebd176b1d109aa9858365b12ed8a",
    "outcome": "e383b96f30d9598344ad8a358947a0836c92704c3866e8547dbbc197a1e4bf28",
    "profile": "425c0c877594ad36086acca49ff007b7924dc4512d4993561118a95c81bd9f19",
}


def artifact_sha256(path: pathlib.Path) -> str:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ContractError("cannot read artifact") from error
    return hashlib.sha256(payload).hexdigest()


def load_trusted_schema(path: pathlib.Path, name: str) -> dict[str, Any]:
    if artifact_sha256(path) != SCHEMA_DIGESTS[name]:
        raise ContractError(f"benchmark-{name}: trusted schema digest mismatch")
    schema = load_verified_json(path)
    if not isinstance(schema, dict):
        raise ContractError(f"benchmark-{name}: object schema required")
    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
    ):
        raise ContractError(f"benchmark-{name}: open schema")
    return schema
