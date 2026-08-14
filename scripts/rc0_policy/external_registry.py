"""Read-only canonical JSONL adapter for externally supplied envelopes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import canonical_lf


class ExternalRegistryFailure(ValueError):
    """An external registry stream violates its closed transport format."""


class ExternalEnvelopeRegistry(Protocol):
    def fetch_canonical_lf(self, envelope_sha256: str) -> bytes: ...


@dataclass(frozen=True)
class RegistryEntry:
    envelope_sha256: str
    canonical_lf_bytes: bytes
    schema_id: str
    schema_sha256: str


def _entry(record: bytes) -> RegistryEntry:
    try:
        value = loads_canonical(record)
    except StrictJSONError as error:
        raise ExternalRegistryFailure("REGISTRY_PARSE_INVALID") from error
    if type(value) is not dict or canonical_lf(value) != record:
        raise ExternalRegistryFailure("REGISTRY_CANONICAL_INVALID")
    schema_id = value.get("payload_schema_id")
    schema_sha256 = value.get("payload_schema_sha256")
    if type(schema_id) is not str or type(schema_sha256) is not str:
        raise ExternalRegistryFailure("REGISTRY_METADATA_INVALID")
    return RegistryEntry(
        hashlib.sha256(canonical_bytes(value)).hexdigest(), record, schema_id, schema_sha256
    )


def parse_external_registry_jsonl(raw: bytes) -> tuple[RegistryEntry, ...]:
    """Parse only sorted, unique canonical-LF JSON records from external bytes."""
    if type(raw) is not bytes:
        raise TypeError("external registry bytes are required")
    if not raw or raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or not raw.endswith(b"\n"):
        raise ExternalRegistryFailure("REGISTRY_TRANSPORT_INVALID")
    lines = raw.split(b"\n")
    if lines[-1] or any(not line for line in lines[:-1]):
        raise ExternalRegistryFailure("REGISTRY_TRANSPORT_INVALID")
    entries = tuple(_entry(line + b"\n") for line in lines[:-1])
    digests = tuple(entry.envelope_sha256 for entry in entries)
    if digests != tuple(sorted(digests)) or len(set(digests)) != len(digests):
        raise ExternalRegistryFailure("REGISTRY_ORDER_OR_DUPLICATE_INVALID")
    return entries
