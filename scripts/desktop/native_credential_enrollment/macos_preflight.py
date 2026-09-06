"""Structural signed-envelope contract. Never authenticates or qualifies evidence.

The protected controller must independently verify the Ed25519 signature and
all native observations. Candidate-controlled flags are not trust inputs.
"""
import base64
import binascii
import json
import re
from datetime import datetime, timedelta, timezone

from . import macos
from .evidence_io import shape_errors
from .macos_bindings import canonical_digest

CONTEXT_FIELDS = {"source_revision", "workflow_run_id", "namespace_sha256", "signer_key_id"}
ENVELOPE_FIELDS = CONTEXT_FIELDS | {
    "schema_version", "row_sha256", "expected_tuples_sha256", "started_at",
    "finished_at", "cleanup_verified", "signature",
}
SIGNATURE_DOMAIN = b"runne/macos-xpc-service-qualification/v1\x00"


def context_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != CONTEXT_FIELDS or shape_errors(value):
        return ["run context fields are invalid"]
    if not isinstance(value["source_revision"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["source_revision"]):
        return ["run context requires an immutable source revision"]
    if any(not macos._sha256(value[field]) for field in ("namespace_sha256", "signer_key_id")):
        return ["run namespace or signer binding is invalid"]
    if not isinstance(value["workflow_run_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["workflow_run_id"]):
        return ["run workflow identity is invalid"]
    return []


def signing_payload(envelope: dict[str, object]) -> bytes:
    """Exact domain-separated signing bytes; contains only redacted metadata."""
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    return SIGNATURE_DOMAIN + json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def validate_envelope(
    value: object, row: object, expected_tuples: object, context: object,
    now: datetime | None = None,
) -> list[str]:
    """Check bindings/freshness only; a well-shaped fake signature can pass."""
    errors = context_errors(context)
    errors += macos.validate_row(row)
    errors += macos.validate_expected_tuples(expected_tuples, [row])
    if errors:
        return errors
    if not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS or shape_errors(value):
        return ["signed envelope fields are invalid"]
    if value["schema_version"] != "macos-xpc-service-signed-envelope.v1":
        return ["signed envelope version is invalid"]
    if any(value[field] != context[field] for field in CONTEXT_FIELDS):
        return ["signed envelope does not match the protected run context"]
    if value["workflow_run_id"] != row["runner"]["workflow_run_id"]:
        return ["signed envelope and row workflow identities differ"]
    if value["row_sha256"] != canonical_digest(row) or value["expected_tuples_sha256"] != canonical_digest(expected_tuples):
        return ["signed envelope subject digest mismatch"]
    if value["cleanup_verified"] is not True:
        return ["terminal exact-namespace cleanup is missing"]
    errors.extend(_signature_shape_errors(value["signature"]))
    errors.extend(_freshness_errors(value, now or datetime.now(timezone.utc)))
    return errors


def _signature_shape_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != {"algorithm", "value"} or value.get("algorithm") != "ed25519":
        return ["detached signature shape is invalid"]
    signature = value.get("value")
    if not isinstance(signature, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}==", signature):
        return ["detached signature encoding is invalid"]
    try:
        decoded = base64.b64decode(signature, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return ["detached signature encoding is invalid"]
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).decode("ascii") != signature:
        return ["detached signature encoding is invalid"]
    return []


def _freshness_errors(value: dict[str, object], now: datetime) -> list[str]:
    timestamps = []
    for field in ("started_at", "finished_at"):
        item = value[field]
        if not isinstance(item, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", item):
            return ["signed run timestamps are invalid"]
        try:
            timestamps.append(datetime.strptime(item, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc))
        except ValueError:
            return ["signed run timestamps are invalid"]
    start, finish = timestamps
    if not start <= finish <= now or finish - start > timedelta(hours=2) or now - start > timedelta(hours=24):
        return ["signed run is stale, future-dated, or exceeds its bounded window"]
    return []
