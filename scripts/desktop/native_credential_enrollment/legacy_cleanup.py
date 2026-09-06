"""Validate legacy cleanup evidence structure, never attest or grant authority.

Expected identities must come from protected candidate/run context, not from
the supplied document. Signature verification and native execution are separate
requirements of a future versioned migration profile. D1.1a legacy import is
unsupported; no positive legacy gate is required. This module deliberately
does not produce qualified receipts.
"""
from __future__ import annotations

SCHEMA_VERSION = "legacy-source-cleanup-evidence.v1"
SELECTORS = frozenset({
    "authorized_import", "durable_cutover", "replacement_denied",
    "ambiguous_source_denied", "exact_source_deleted",
    "restart_after_delete_before_confirmation", "reimport_denied",
})
FIELDS = frozenset({
    "schema_version", "candidate_sha256", "tuple_sha256", "workflow_run_id", "selectors",
})


def _digest(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 64 and value != "0" * 64
            and all(char in "0123456789abcdef" for char in value))


def validate_evidence(
    value: object, *, candidate_sha256: str, tuple_sha256: str, workflow_run_id: str,
) -> list[str]:
    """Return redacted structural errors; an empty list is not qualification."""
    if not _digest(candidate_sha256) or not _digest(tuple_sha256):
        return ["expected candidate or tuple is invalid"]
    if not isinstance(workflow_run_id, str) or not workflow_run_id.strip():
        return ["expected protected workflow run is missing"]
    if not isinstance(value, dict) or set(value) != FIELDS:
        return ["legacy evidence envelope is not exact"]
    if value["schema_version"] != SCHEMA_VERSION:
        return ["legacy evidence schema is unsupported"]
    if (value["candidate_sha256"] != candidate_sha256
            or value["tuple_sha256"] != tuple_sha256
            or value["workflow_run_id"] != workflow_run_id):
        return ["legacy evidence candidate, tuple or run mismatches"]
    selectors = value["selectors"]
    if not isinstance(selectors, dict) or set(selectors) != SELECTORS:
        return ["legacy evidence selector set is incomplete or unknown"]
    for receipt in selectors.values():
        if (not isinstance(receipt, dict)
                or set(receipt) != {"status", "observation_sha256"}
                or receipt["status"] != "verified"
                or not _digest(receipt["observation_sha256"])):
            return ["legacy evidence receipt is invalid"]
    return []
