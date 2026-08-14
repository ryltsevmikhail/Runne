"""V4 matrix binds the retained verified V3 handoff; no caller-supplied cells."""
from __future__ import annotations

import hashlib
import json
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from scripts.rc0_policy.adjunct_schema_validation import validate_adjunct_schema_instance
from scripts.rc0_policy.canonical import loads_canonical
from scripts.rc0_policy.external_envelope import PrincipalBinding, VerifiedEnvelope, require_fixture_verified
from scripts.rc0_policy.platform_matrix import normalized_platform_mapping_payload
from scripts.rc0_policy.qualified_subject_v3 import VerifiedRc0HandoffV3
from scripts.rc0_policy.production_security_review import FixtureTrustedConsumptionContext, _context, _envelope_current

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ID = "gocode.release.platform-qualification-matrix/4"
_TOKEN = object()


class PlatformMatrixV4Failure(ValueError): pass
def _fail(code: str) -> None: raise PlatformMatrixV4Failure(code)
def _sha(value: bytes) -> str: return hashlib.sha256(value).hexdigest()
def _principal(value: VerifiedEnvelope) -> PrincipalBinding: return PrincipalBinding(value.issuer_role, value.issuer_subject_id, value.issuer_controlling_account_id, value.issuer_delegated_session_id, value.issuer_lane_id)


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class VerifiedPlatformMatrixV4:
    envelope_sha256: str; platform_qualified_subject_envelope_sha256: str; normalized_platform_mapping_payload_sha256: str
    _envelope: VerifiedEnvelope = field(repr=False, compare=False); _subject: VerifiedRc0HandoffV3 = field(repr=False, compare=False); _context: FixtureTrustedConsumptionContext = field(repr=False, compare=False); _token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_token"}: raise TypeError("VerifiedPlatformMatrixV4 is verifier-owned")
        for name, value in fields.items(): object.__setattr__(self, name, value)
        object.__setattr__(self, "_token", token)
    def require_verified(self, context: FixtureTrustedConsumptionContext) -> None:
        state = _ISSUED.get(self)
        if type(self) is not VerifiedPlatformMatrixV4 or self._token is not _TOKEN or state is None or context is not state[2] or (self._envelope, self._subject, self._context) != state: _fail("MATRIX_HANDLE_INVALID")
        payload = _verify(*state)
        if (self.envelope_sha256, self.platform_qualified_subject_envelope_sha256, self.normalized_platform_mapping_payload_sha256) != (state[0].envelope_sha256, payload["platform_qualified_subject_envelope_sha256"], payload["normalized_platform_mapping_payload_sha256"]): _fail("MATRIX_HANDLE_INVALID")


_ISSUED: weakref.WeakKeyDictionary[VerifiedPlatformMatrixV4, tuple[VerifiedEnvelope, VerifiedRc0HandoffV3, FixtureTrustedConsumptionContext]] = weakref.WeakKeyDictionary()


def _verify(envelope: object, subject: object, context: object) -> dict[str, object]:
    if type(envelope) is not VerifiedEnvelope or type(subject) is not VerifiedRc0HandoffV3: _fail("MATRIX_INPUT_INVALID")
    context = _context(context)
    try: subject.require_verified(context); require_fixture_verified(envelope); payload = loads_canonical(envelope.payload_canonical_bytes); schema = json.loads((ROOT / "docs/schemas/release-platform-qualification-matrix-v4.schema.json").read_bytes())
    except Exception as error: raise PlatformMatrixV4Failure("MATRIX_CONTEXT_INVALID") from error
    if envelope.payload_schema_id != SCHEMA_ID or validate_adjunct_schema_instance(schema, payload): _fail("MATRIX_SCHEMA_INVALID")
    predecessor = subject._predecessor
    expected = _sha(normalized_platform_mapping_payload(predecessor._attestations))
    identity = _principal(envelope)
    issuer = {"role_id": identity.role_id, "subject_id": identity.subject_id, "controlling_account_id": identity.controlling_account_id, "delegated_session_id": identity.delegated_session_id, "lane_id": identity.lane_id}
    if identity != predecessor.issuer_identity or payload.get("issuer") != issuer or payload.get("platform_qualified_subject_envelope_sha256") != subject.envelope_sha256 or payload.get("predecessor_subject_envelope_sha256") != predecessor.envelope_sha256 or payload.get("normalized_platform_mapping_payload_sha256") != expected or expected != subject.normalized_platform_mapping_payload_sha256 or payload.get("issuer_key_epoch") != envelope.issuer_key_epoch or payload.get("revocation_epoch") != envelope.issuer_revocation_epoch or not _envelope_current(envelope, context): _fail("MATRIX_BINDING_INVALID")
    return payload


def verify_platform_matrix_v4(envelope: VerifiedEnvelope, subject: VerifiedRc0HandoffV3, context: FixtureTrustedConsumptionContext) -> VerifiedPlatformMatrixV4:
    payload = _verify(envelope, subject, context)
    view = VerifiedPlatformMatrixV4(_TOKEN, envelope_sha256=envelope.envelope_sha256, platform_qualified_subject_envelope_sha256=payload["platform_qualified_subject_envelope_sha256"], normalized_platform_mapping_payload_sha256=payload["normalized_platform_mapping_payload_sha256"], _envelope=envelope, _subject=subject, _context=context)
    _ISSUED[view] = (envelope, subject, context); view.require_verified(context)
    return view


def validate_platform_matrix_v4(*_: object, **__: object) -> None: _fail("SUPERSEDED_SURROGATE_UNSUPPORTED")
def verify_platform_matrix_v4_production(*_: object, **__: object) -> None: _fail("PRODUCTION_AUTHENTICATOR_NOT_PROVISIONED")
