"""Normalize authenticated RC0 gate outcomes without issuing authority artifacts."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal
from weakref import WeakKeyDictionary

from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical


OUTCOME_TRUST_DOMAIN = b"gocode.rc0.operational-gate-trust/1\0"
_TOKEN = object()
_DIGEST = re.compile(r"[0-9a-f]{64}")
_STAGES = frozenset(("SOURCE_CANDIDATE", "PRODUCTION_QUALIFICATION"))
_RESULTS = {
    "PASS": ("PASS", None, "PASS"),
    "FAIL": ("BLOCKED", "REQUIRED_GATE_FAILED", "BLOCKED(REQUIRED_GATE_FAILED)"),
    "NOT_RUN": ("BLOCKED", "REQUIRED_GATE_NOT_RUN", "BLOCKED(REQUIRED_GATE_NOT_RUN)"),
}


class OperationalVerificationError(RuntimeError):
    """A nonzero parser, trust, rollback or role failure before normalization."""

    exit_code = 1

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class OperationalTrustVerification:
    verification_domain: Literal["FIXTURE_ONLY"]
    transcript_sha256: str
    snapshot_sha256: str


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class VerifiedRequiredGateResults:
    """Opaque verifier-owned view with no token or mutable gate snapshot."""

    def __init__(self, token: object, /) -> None:
        if token is not _TOKEN:
            raise TypeError("verified required-gate results are verifier-owned")


_VERIFIED: WeakKeyDictionary[VerifiedRequiredGateResults, tuple[bytes, str]] = WeakKeyDictionary()


def _freeze(value: object) -> object:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _snapshot(raw_results: object) -> tuple[object, bytes, str]:
    if type(raw_results) is not list:
        raise OperationalVerificationError("REQUIRED_GATE_SHAPE_INVALID")
    try:
        snapshot_bytes = canonical_bytes(raw_results)
        snapshot = loads_canonical(snapshot_bytes)
    except (StrictJSONError, TypeError) as error:
        raise OperationalVerificationError("REQUIRED_GATE_SHAPE_INVALID") from error
    if type(snapshot) is not list:
        raise OperationalVerificationError("REQUIRED_GATE_SHAPE_INVALID")
    for gate in snapshot:
        _validate_gate_shape(gate)
    return _freeze(snapshot), snapshot_bytes, hashlib.sha256(snapshot_bytes).hexdigest()


def _validate_gate_shape(gate: object) -> None:
    if type(gate) is not dict:
        raise OperationalVerificationError("REQUIRED_GATE_SHAPE_INVALID")
    outcome = gate.get("execution_outcome")
    expected = _RESULTS.get(outcome)
    required = {"gate_id", "stage", "execution_outcome", "gate_result", "binding"}
    if expected is None or type(gate.get("gate_id")) is not str or not gate["gate_id"]:
        raise OperationalVerificationError("REQUIRED_GATE_SHAPE_INVALID")
    if gate.get("stage") not in _STAGES or type(gate.get("binding")) is not dict:
        raise OperationalVerificationError("REQUIRED_GATE_SHAPE_INVALID")
    result, reason, _ = expected
    expected_fields = required if reason is None else required | {"blocked_reason"}
    if set(gate) != expected_fields or gate.get("gate_result") != result:
        raise OperationalVerificationError("REQUIRED_GATE_SHAPE_INVALID")
    if reason is not None and gate.get("blocked_reason") != reason:
        raise OperationalVerificationError("REQUIRED_GATE_SHAPE_INVALID")


def _trust(
    callback: Callable[[object, bytes], object], snapshot: object, snapshot_bytes: bytes, snapshot_sha256: str,
) -> None:
    transcript = OUTCOME_TRUST_DOMAIN + snapshot_bytes
    try:
        trust = callback(snapshot, transcript)
    except OperationalVerificationError:
        raise
    except Exception as error:
        code = getattr(error, "code", None)
        if type(code) is str and code:
            raise OperationalVerificationError(code) from error
        if type(error) is ValueError and str(error):
            raise OperationalVerificationError(str(error)) from error
        raise OperationalVerificationError("OPERATIONAL_TRUST_INVALID") from error
    if type(trust) is not OperationalTrustVerification:
        raise OperationalVerificationError("OPERATIONAL_TRUST_INVALID")
    if (
        trust.verification_domain != "FIXTURE_ONLY"
        or _DIGEST.fullmatch(trust.transcript_sha256) is None
        or _DIGEST.fullmatch(trust.snapshot_sha256) is None
        or trust.transcript_sha256 != hashlib.sha256(transcript).hexdigest()
        or trust.snapshot_sha256 != snapshot_sha256
    ):
        raise OperationalVerificationError("OPERATIONAL_TRUST_INVALID")


def verify_required_gate_results(
    raw_results: object, verify_operational: Callable[[object, bytes], object],
) -> VerifiedRequiredGateResults:
    """Freeze and authenticate a closed gate snapshot before minting its view."""
    if not callable(verify_operational):
        raise OperationalVerificationError("VERIFIER_INVALID")
    snapshot, snapshot_bytes, snapshot_sha256 = _snapshot(raw_results)
    _trust(verify_operational, snapshot, snapshot_bytes, snapshot_sha256)
    if _snapshot(raw_results)[1] != snapshot_bytes:
        raise OperationalVerificationError("REQUIRED_GATE_RACE_INVALID")
    verified = VerifiedRequiredGateResults(_TOKEN)
    _VERIFIED[verified] = (snapshot_bytes, snapshot_sha256)
    return verified


def _verified_snapshot(verified: VerifiedRequiredGateResults) -> list[object]:
    if type(verified) is not VerifiedRequiredGateResults or verified not in _VERIFIED:
        raise OperationalVerificationError("VERIFIED_RESULTS_INVALID")
    snapshot_bytes, snapshot_sha256 = _VERIFIED[verified]
    if hashlib.sha256(snapshot_bytes).hexdigest() != snapshot_sha256:
        raise OperationalVerificationError("VERIFIED_RESULTS_INVALID")
    snapshot = loads_canonical(snapshot_bytes)
    if type(snapshot) is not list:
        raise OperationalVerificationError("VERIFIED_RESULTS_INVALID")
    return snapshot


def normalize_verified_required_gate_results(
    verified: VerifiedRequiredGateResults, expected_gate_ids: Sequence[str], expected_binding: Mapping[str, object],
) -> str:
    """Map an authenticated exact set to PASS or one exact RC0 BLOCKED code."""
    expected_ids = tuple(expected_gate_ids)
    if not expected_ids or any(type(item) is not str or not item for item in expected_ids):
        raise OperationalVerificationError("EXPECTED_GATE_SET_INVALID")
    if len(set(expected_ids)) != len(expected_ids) or not isinstance(expected_binding, Mapping):
        raise OperationalVerificationError("EXPECTED_GATE_SET_INVALID")
    try:
        expected = loads_canonical(canonical_bytes(dict(expected_binding)))
    except (StrictJSONError, TypeError) as error:
        raise OperationalVerificationError("EXPECTED_GATE_SET_INVALID") from error
    snapshot = _verified_snapshot(verified)
    if len(snapshot) != len(expected_ids):
        return "BLOCKED(REQUIRED_GATE_MISMATCH)"
    by_id: dict[str, dict[str, object]] = {}
    for gate in snapshot:
        _validate_gate_shape(gate)
        gate_id = gate["gate_id"]
        if gate_id in by_id:
            return "BLOCKED(REQUIRED_GATE_MISMATCH)"
        by_id[gate_id] = gate
    if set(by_id) != set(expected_ids):
        return "BLOCKED(REQUIRED_GATE_MISMATCH)"
    for gate_id in expected_ids:
        if by_id[gate_id]["binding"] != expected:
            return "BLOCKED(REQUIRED_GATE_MISMATCH)"
    for gate_id in expected_ids:
        code = _RESULTS[by_id[gate_id]["execution_outcome"]][2]
        if code != "PASS":
            return code
    return "PASS"


def normalize_required_gate_results(
    raw_results: object, expected_gate_ids: Sequence[str], expected_binding: Mapping[str, object],
    verify_operational: Callable[[object, bytes], object],
) -> str:
    """Authenticate first, then return a normalized code without writing artifacts."""
    return normalize_verified_required_gate_results(
        verify_required_gate_results(raw_results, verify_operational), expected_gate_ids, expected_binding,
    )
