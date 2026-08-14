"""Verification-only boundary for fixture and externally signed envelopes."""

from __future__ import annotations

import hashlib
import re
from datetime import date, datetime
from dataclasses import dataclass, field
from typing import Callable, Mapping

from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical
from scripts.rc0_policy.adjunct_schema_validation import (
    parse_adjunct_schema,
    validate_adjunct_schema_instance,
)


DOMAIN = b"gocode.external-signed-envelope/1"
SCHEMA_VERSION = "gocode.rc0.external-signed-envelope/1"
FIXTURE_ONLY = "FIXTURE_ONLY"
PRODUCTION = "PRODUCTION"
PRODUCTION_BOUNDARY_ENTRYPOINTS: tuple[str, ...] = ()
_TOKEN = object()
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{6}))?Z")
_FIELDS = frozenset((
    "schema_version", "payload_schema_id", "payload_schema_sha256", "payload_sha256",
    "payload", "issuer", "issuer_key_id", "issuer_key_epoch", "issuer_subject_id",
    "issuer_controlling_account_id", "issuer_delegated_session_id", "issuer_lane_id",
    "issuer_role", "issuer_revocation_epoch", "signature_profile_id", "issued_at",
    "not_before", "expires_at", "signature",
))


class EnvelopeFailure(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PrincipalBinding:
    role_id: str
    subject_id: str
    controlling_account_id: str
    delegated_session_id: str
    lane_id: str


@dataclass(frozen=True)
class TrustVerification:
    verification_domain: str
    transcript_sha256: str
    issuer: str
    issuer_key_id: str
    issuer_key_epoch: int
    issuer_revocation_epoch: int
    signature_profile_id: str
    principal: PrincipalBinding


SignatureVerifier = Callable[[bytes, str, str], TrustVerification | None]
EnvelopeResolver = Callable[[str], bytes]


class AdjunctSchemaStore:
    """An injected, exact-byte adjunct schema inventory and validator."""

    def __init__(self, schemas: Mapping[str, bytes]) -> None:
        if not isinstance(schemas, Mapping):
            raise TypeError("adjunct schemas require provisioned schema bytes")
        copied = tuple(sorted(schemas.items()))
        if not copied or any(type(key) is not str or type(value) is not bytes for key, value in copied):
            raise TypeError("adjunct schemas require a non-empty string-to-bytes mapping")
        self._schemas = copied
        self._parsed_schemas = tuple((schema_id, parse_adjunct_schema(raw, schema_id)) for schema_id, raw in copied)

    def schema_digests(self) -> tuple[tuple[str, str], ...]:
        return tuple((schema_id, sha256_digest(raw)) for schema_id, raw in self._schemas)

    def validate(self, schema_id: str, schema_sha256: str, value: object) -> None:
        expected = dict(self._schemas).get(schema_id)
        if expected is None or sha256_digest(expected) != schema_sha256:
            raise EnvelopeFailure("SCHEMA_INVALID")
        schema = dict(self._parsed_schemas).get(schema_id)
        if schema is None:
            raise EnvelopeFailure("SCHEMA_INVALID")
        diagnostics = validate_adjunct_schema_instance(schema, value)
        if diagnostics:
            raise EnvelopeFailure("SCHEMA_INVALID")


@dataclass(frozen=True, init=False)
class VerifiedEnvelope:
    payload_schema_id: str
    payload_schema_sha256: str
    payload_sha256: str
    payload_canonical_bytes: bytes
    envelope_sha256: str
    envelope_canonical_bytes: bytes
    verification_domain: str
    issuer: str
    issuer_key_id: str
    issuer_subject_id: str
    issuer_controlling_account_id: str
    issuer_delegated_session_id: str
    issuer_lane_id: str
    issuer_role: str
    issuer_key_epoch: int
    issuer_revocation_epoch: int
    signature_profile_id: str
    issued_at: str
    not_before: str
    expires_at: str
    issued_at_epoch_seconds: int
    not_before_epoch_seconds: int
    expires_at_epoch_seconds: int
    trust: TrustVerification
    _verification_token: object = field(repr=False, compare=False)

    def __init__(self, verification_token: object, /, **fields: object) -> None:
        if verification_token is not _TOKEN:
            raise TypeError("VerifiedEnvelope is verifier-owned")
        expected = set(self.__dataclass_fields__) - {"_verification_token"}
        if set(fields) != expected:
            raise TypeError("VerifiedEnvelope requires verified fields")
        for name, value in fields.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_verification_token", verification_token)


def sha256_digest(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise TypeError("digest input must be bytes")
    return hashlib.sha256(raw).hexdigest()


def canonical_lf(value: object) -> bytes:
    return canonical_bytes(value) + b"\n"


def signature_transcript(unsigned_envelope: Mapping[str, object]) -> bytes:
    if not isinstance(unsigned_envelope, Mapping):
        raise TypeError("unsigned envelope must be a mapping")
    unsigned = canonical_bytes(dict(unsigned_envelope))
    return len(DOMAIN).to_bytes(4, "big") + DOMAIN + len(unsigned).to_bytes(8, "big") + unsigned


def _parse(raw: bytes) -> dict[str, object]:
    try:
        parsed = loads_canonical(raw)
        if type(parsed) is not dict or canonical_bytes(parsed) != raw:
            raise EnvelopeFailure("PARSE_INVALID")
    except StrictJSONError as error:
        raise EnvelopeFailure("PARSE_INVALID") from error
    if set(parsed) != _FIELDS:
        raise EnvelopeFailure("FIELDS_INVALID")
    return parsed


def _timestamp(value: object) -> int:
    if type(value) is not str:
        raise EnvelopeFailure("METADATA_INVALID")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise EnvelopeFailure("METADATA_INVALID")
    try:
        parsed = datetime(*map(int, match.groups()[:6]))
    except ValueError as error:
        raise EnvelopeFailure("METADATA_INVALID") from error
    seconds = (parsed.date() - date(1970, 1, 1)).days * 86_400 + parsed.hour * 3_600 + parsed.minute * 60 + parsed.second
    return seconds * 1_000_000 + int(match.group(7) or "0")


def timestamp_epoch_seconds(value: object) -> int:
    """Parse the closed UTC timestamp profile into whole epoch seconds."""
    return _timestamp(value) // 1_000_000


def _metadata(envelope: dict[str, object], now: int) -> None:
    strings = (
        "schema_version", "payload_schema_id", "payload_schema_sha256", "payload_sha256",
        "issuer", "issuer_key_id", "issuer_subject_id", "issuer_controlling_account_id",
        "issuer_delegated_session_id", "issuer_lane_id", "issuer_role",
        "signature_profile_id", "signature",
    )
    if any(type(envelope[name]) is not str or not envelope[name] for name in strings):
        raise EnvelopeFailure("METADATA_INVALID")
    if envelope["schema_version"] != SCHEMA_VERSION:
        raise EnvelopeFailure("METADATA_INVALID")
    if any(_DIGEST.fullmatch(envelope[name]) is None for name in ("payload_schema_sha256", "payload_sha256")):
        raise EnvelopeFailure("METADATA_INVALID")
    integers = ("issuer_key_epoch", "issuer_revocation_epoch")
    if type(now) is not int or isinstance(now, bool) or any(type(envelope[name]) is not int or envelope[name] < 0 for name in integers):
        raise EnvelopeFailure("METADATA_INVALID")
    not_before, issued_at, expires_at = (_timestamp(envelope[name]) for name in ("not_before", "issued_at", "expires_at"))
    now_microseconds = now * 1_000_000
    if not not_before <= issued_at <= expires_at or now_microseconds < issued_at or now_microseconds < not_before or now_microseconds > expires_at:
        raise EnvelopeFailure("TIME_INVALID")
    fixture_metadata = envelope["issuer"] == FIXTURE_ONLY or envelope["signature_profile_id"] == FIXTURE_ONLY
    if fixture_metadata and (envelope["issuer"] != FIXTURE_ONLY or envelope["signature_profile_id"] != FIXTURE_ONLY):
        raise EnvelopeFailure("FIXTURE_GUARD")


def _trust_matches(envelope: dict[str, object], transcript: bytes, trust: TrustVerification) -> bool:
    if type(trust) is not TrustVerification or type(trust.principal) is not PrincipalBinding:
        return False
    fixture_metadata = envelope["issuer"] == FIXTURE_ONLY
    if trust.verification_domain != (FIXTURE_ONLY if fixture_metadata else PRODUCTION):
        return False
    return (
        trust.transcript_sha256 == sha256_digest(transcript)
        and trust.issuer == envelope["issuer"]
        and trust.issuer_key_id == envelope["issuer_key_id"]
        and trust.issuer_key_epoch == envelope["issuer_key_epoch"]
        and trust.issuer_revocation_epoch == envelope["issuer_revocation_epoch"]
        and trust.signature_profile_id == envelope["signature_profile_id"]
        and trust.principal == PrincipalBinding(
            envelope["issuer_role"], envelope["issuer_subject_id"],
            envelope["issuer_controlling_account_id"], envelope["issuer_delegated_session_id"],
            envelope["issuer_lane_id"],
        )
    )


def verify_signed_envelope(
    raw: bytes, schemas: AdjunctSchemaStore, verify_signature: SignatureVerifier, now_epoch_seconds: int,
) -> VerifiedEnvelope:
    if type(schemas) is not AdjunctSchemaStore or not callable(verify_signature):
        raise TypeError("envelope verifier requires injected schema and signature callbacks")
    envelope = _parse(raw)
    _metadata(envelope, now_epoch_seconds)
    payload = canonical_bytes(envelope["payload"])
    if sha256_digest(payload) != envelope["payload_sha256"]:
        raise EnvelopeFailure("PAYLOAD_DIGEST_MISMATCH")
    schemas.validate(envelope["payload_schema_id"], envelope["payload_schema_sha256"], envelope["payload"])
    unsigned = dict(envelope)
    signature = unsigned.pop("signature")
    transcript = signature_transcript(unsigned)
    result = verify_signature(transcript, signature, envelope["signature_profile_id"])
    if result is None:
        raise EnvelopeFailure("TRUST_MISMATCH")
    if type(result) is not TrustVerification:
        raise EnvelopeFailure("TRUST_INVALID")
    if not _trust_matches(envelope, transcript, result):
        raise EnvelopeFailure("TRUST_MISMATCH")
    return VerifiedEnvelope(
        _TOKEN, payload_schema_id=envelope["payload_schema_id"], payload_schema_sha256=envelope["payload_schema_sha256"],
        payload_sha256=envelope["payload_sha256"], payload_canonical_bytes=payload,
        envelope_sha256=sha256_digest(raw), envelope_canonical_bytes=raw,
        verification_domain=result.verification_domain, issuer=envelope["issuer"], issuer_key_id=envelope["issuer_key_id"],
        issuer_subject_id=envelope["issuer_subject_id"], issuer_controlling_account_id=envelope["issuer_controlling_account_id"],
        issuer_delegated_session_id=envelope["issuer_delegated_session_id"], issuer_lane_id=envelope["issuer_lane_id"],
        issuer_role=envelope["issuer_role"], issuer_key_epoch=envelope["issuer_key_epoch"],
        issuer_revocation_epoch=envelope["issuer_revocation_epoch"], signature_profile_id=envelope["signature_profile_id"], trust=result,
        issued_at=envelope["issued_at"], not_before=envelope["not_before"], expires_at=envelope["expires_at"],
        issued_at_epoch_seconds=timestamp_epoch_seconds(envelope["issued_at"]),
        not_before_epoch_seconds=timestamp_epoch_seconds(envelope["not_before"]),
        expires_at_epoch_seconds=timestamp_epoch_seconds(envelope["expires_at"]),
    )


def _require_verified(envelope: VerifiedEnvelope) -> None:
    if type(envelope) is not VerifiedEnvelope or envelope._verification_token is not _TOKEN:
        raise EnvelopeFailure("VERIFIED_INVALID")
    if sha256_digest(envelope.envelope_canonical_bytes) != envelope.envelope_sha256:
        raise EnvelopeFailure("VERIFIED_INVALID")
    parsed = _parse(envelope.envelope_canonical_bytes)
    if canonical_bytes(parsed["payload"]) != envelope.payload_canonical_bytes or sha256_digest(envelope.payload_canonical_bytes) != envelope.payload_sha256:
        raise EnvelopeFailure("VERIFIED_INVALID")
    unsigned = dict(parsed)
    unsigned.pop("signature")
    if not _trust_matches(parsed, signature_transcript(unsigned), envelope.trust):
        raise EnvelopeFailure("VERIFIED_INVALID")
    fields = ("payload_schema_id", "payload_schema_sha256", "payload_sha256", "issuer", "issuer_key_id", "issuer_subject_id", "issuer_controlling_account_id", "issuer_delegated_session_id", "issuer_lane_id", "issuer_role", "issuer_key_epoch", "issuer_revocation_epoch", "signature_profile_id", "issued_at", "not_before", "expires_at")
    if any(getattr(envelope, name) != parsed[name] for name in fields):
        raise EnvelopeFailure("VERIFIED_INVALID")
    expected_domain = FIXTURE_ONLY if parsed["issuer"] == FIXTURE_ONLY else PRODUCTION
    if envelope.verification_domain != expected_domain:
        raise EnvelopeFailure("VERIFIED_INVALID")
    if (timestamp_epoch_seconds(parsed["issued_at"]), timestamp_epoch_seconds(parsed["not_before"]), timestamp_epoch_seconds(parsed["expires_at"])) != (envelope.issued_at_epoch_seconds, envelope.not_before_epoch_seconds, envelope.expires_at_epoch_seconds):
        raise EnvelopeFailure("VERIFIED_INVALID")


def principal_binding(envelope: VerifiedEnvelope) -> PrincipalBinding:
    _require_verified(envelope)
    return envelope.trust.principal


def require_fixture_verified(envelope: VerifiedEnvelope) -> None:
    _require_verified(envelope)
    if envelope.verification_domain != FIXTURE_ONLY or envelope.issuer != FIXTURE_ONLY or envelope.signature_profile_id != FIXTURE_ONLY:
        raise EnvelopeFailure("FIXTURE_GUARD")
