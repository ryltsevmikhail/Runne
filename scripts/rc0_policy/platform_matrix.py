"""Fixture-only platform qualification matrix projection and verifier."""
from __future__ import annotations

import hashlib
import re
import weakref
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.rc0_policy.artifact_closure import ArtifactClosure
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, PrincipalBinding, VerifiedEnvelope, require_fixture_verified
from scripts.rc0_policy.platform_attestation import PlatformAttestationView
from scripts.rc0_policy.platform_attestation_evidence import HostIdentity
from scripts.rc0_policy.platform_attestation_profiles import ProfileRow

if TYPE_CHECKING:
    from scripts.rc0_policy.qualified_subject import QualifiedSubjectView


ROOT = Path(__file__).resolve().parents[2]
_TOKEN = object()
_SCHEMA = "gocode.release.platform-qualification-matrix/2"
_SCHEMA_PATH = ROOT / "docs/schemas/release-platform-qualification-matrix-v2.schema.json"
_SCOPES = (
    "linux-ubuntu-24_04-x86_64-production",
    "macos-14-arm64-development-preview",
    "windows-11-24h2-x86_64-production",
)
_HEX = re.compile(r"[0-9a-f]{64}")


class MatrixFailure(ValueError):
    """A platform-matrix contract mismatch."""


def _fail(code: str) -> None: raise MatrixFailure(code)
def _sha(value: bytes) -> str: return hashlib.sha256(value).hexdigest()
def _digest(value: object) -> bool: return type(value) is str and _HEX.fullmatch(value) is not None
def _same_principal(actual: object, expected: object) -> bool:
    if type(actual) is not PrincipalBinding or type(expected) is not PrincipalBinding: return False
    left = (actual.role_id, actual.subject_id, actual.controlling_account_id, actual.delegated_session_id, actual.lane_id)
    right = (expected.role_id, expected.subject_id, expected.controlling_account_id, expected.delegated_session_id, expected.lane_id)
    return all(type(item) is str for item in (*left, *right)) and left == right


def _host(value: object) -> HostIdentity:
    if type(value) is not HostIdentity:
        _fail("MATRIX_ATTESTATION_INVALID")
    fields = (value.os_family, value.os_version, value.os_build, value.kernel_or_image_sha256, value.architecture, value.native_mode)
    if any(type(item) is not str for item in fields) or value.native_mode != "native" or not _digest(value.kernel_or_image_sha256):
        _fail("MATRIX_ATTESTATION_INVALID")
    return value


def _profile(value: object) -> ProfileRow:
    if type(value) is not ProfileRow or type(value.profile_id) is not str or not value.profile_id or type(value.profile_revision) not in {int, str} or isinstance(value.profile_revision, bool) or type(value.profile_sha256) not in {str, type(None)} or type(value.state) is not str or value.state not in {"required", "external_canary_only", "disabled_by_policy", "backend_unavailable"} or not _digest(value.evidence_envelope_sha256):
        _fail("MATRIX_ATTESTATION_INVALID")
    if value.state in {"required", "external_canary_only"} and not _digest(value.profile_sha256):
        _fail("MATRIX_ATTESTATION_INVALID")
    if value.state in {"disabled_by_policy", "backend_unavailable"} and value.profile_sha256 is not None:
        _fail("MATRIX_ATTESTATION_INVALID")
    return value


def _artifact(value: object) -> ArtifactClosure:
    if type(value) is not ArtifactClosure or type(value.artifact_slot_id) is not str or not value.artifact_slot_id or type(value.relative_path) is not str or not value.relative_path or type(value.size) is not int or isinstance(value.size, bool) or value.size < 0 or any(not _digest(item) for item in (value.artifact_sha256, value.artifact_manifest_payload_sha256, value.product_manifest_payload_sha256)) or value.locator != f"cas:sha256:{value.artifact_sha256}":
        _fail("MATRIX_ATTESTATION_INVALID")
    return value


def _attestations(values: Sequence[PlatformAttestationView]) -> tuple[PlatformAttestationView, ...]:
    if type(values) not in (tuple, list) or len(values) != 3:
        _fail("MATRIX_ATTESTATION_SET_MISMATCH")
    result = tuple(values)
    if any(type(value) is not PlatformAttestationView for value in result):
        _fail("MATRIX_ATTESTATION_SET_MISMATCH")
    for value in result:
        try: value._require_current_integrity()
        except Exception as error: raise MatrixFailure("MATRIX_ATTESTATION_SET_MISMATCH") from error
    scopes = tuple(sorted(value.platform_scope_id for value in result))
    if scopes != _SCOPES or len({id(value) for value in result}) != 3:
        _fail("MATRIX_ATTESTATION_SET_MISMATCH")
    return result


def _cell(value: PlatformAttestationView) -> dict[str, object]:
    host = _host(value.host)
    if type(value.platform_scope_id) is not str or type(value.qualification_class) is not str or value.qualification_class not in {"production", "development_preview"} or type(value.support_disposition) is not str or value.support_disposition not in {"supported", "unsupported"} or type(value.repository_id) is not str or value.repository_id != "gocode" or host.os_family not in {"Ubuntu", "Windows", "macOS"} or host.architecture not in {"x86_64", "arm64"}:
        _fail("MATRIX_ATTESTATION_INVALID")
    if type(value.profile_rows) is not tuple or type(value.closures) is not tuple or type(value.evidence_envelope_sha256s) is not tuple:
        _fail("MATRIX_ATTESTATION_INVALID")
    profiles = tuple(_profile(row) for row in value.profile_rows)
    artifacts = tuple(_artifact(row) for row in value.closures)
    digests = value.evidence_envelope_sha256s
    if not profiles or not artifacts or not digests or any(not _digest(item) for item in digests) or len(set(row.profile_id for row in profiles)) != len(profiles) or len(set(row.artifact_slot_id for row in artifacts)) != len(artifacts) or len(set(digests)) != len(digests):
        _fail("MATRIX_ATTESTATION_INVALID")
    return {
        "platform_scope_id": value.platform_scope_id,
        "qualification_class": value.qualification_class,
        "support_disposition": value.support_disposition,
        "os_family": host.os_family, "os_version": host.os_version, "os_build": host.os_build,
        "kernel_or_image_sha256": host.kernel_or_image_sha256, "architecture": host.architecture,
        "native_mode": host.native_mode,
        "profile_rows": [{"profile_id": row.profile_id, "profile_revision": row.profile_revision, "profile_sha256": row.profile_sha256, "state": row.state, "evidence_envelope_sha256": row.evidence_envelope_sha256} for row in sorted(profiles, key=lambda row: row.profile_id.encode())],
        "artifact_rows": [{"artifact_slot_id": row.artifact_slot_id, "relative_path": row.relative_path, "sha256": row.artifact_sha256, "size": row.size, "locator": row.locator, "artifact_manifest_payload_sha256": row.artifact_manifest_payload_sha256, "product_manifest_payload_sha256": row.product_manifest_payload_sha256} for row in sorted(artifacts, key=lambda row: row.artifact_slot_id.encode())],
        "evidence_envelope_sha256s": sorted(digests, key=str.encode),
    }


def normalized_platform_mapping_payload(attestations: Sequence[PlatformAttestationView]) -> bytes:
    """Encode the exact scope/profile/artifact/evidence mapping preimage."""
    values = _attestations(attestations)
    cells = sorted((_cell(value) for value in values), key=lambda cell: str(cell["platform_scope_id"]).encode())
    return canonical_bytes({"schema_version": "gocode.rc0.normalized-platform-mapping/1", "repository_id": "gocode", "cells": cells})


@dataclass(frozen=True, init=False, eq=False, slots=True, weakref_slot=True)
class VerifiedMatrixView:
    envelope_sha256: str; platform_qualified_subject_envelope_sha256: str; normalized_platform_mapping_payload_sha256: str; normalized_platform_mapping_payload_bytes: bytes; _matrix_envelope: VerifiedEnvelope; _subject: QualifiedSubjectView; _canonical_source_bytes: bytes; _verification_token: object = field(repr=False, compare=False)
    def __init__(self, token: object, /, **fields: object) -> None:
        if token is not _TOKEN or set(fields) != set(self.__dataclass_fields__) - {"_verification_token"}: raise TypeError("VerifiedMatrixView is verifier-owned")
        for name, value in fields.items(): object.__setattr__(self, name, value)
        object.__setattr__(self, "_verification_token", token)
    def require_verified(self, now_epoch_seconds: int) -> None:
        state = _VIEWS.get(self)
        if type(self) is not VerifiedMatrixView or self._verification_token is not _TOKEN or state is None: _fail("MATRIX_VERIFIED_INVALID")
        try: fields, source = _verify(state.matrix, state.subject, now_epoch_seconds)
        except Exception as error: raise MatrixFailure("MATRIX_VERIFIED_INVALID") from error
        actual = _fingerprint(_public(self), self._canonical_source_bytes)
        if not _same_public(self, state) or self._matrix_envelope is not state.matrix or self._subject is not state.subject or type(self._canonical_source_bytes) is not bytes or source != self._canonical_source_bytes or actual != state.fingerprint or _fingerprint(fields, source) != state.fingerprint: _fail("MATRIX_VERIFIED_INVALID")


@dataclass(frozen=True)
class _State: matrix: VerifiedEnvelope; subject: QualifiedSubjectView; public: tuple[object, ...]; source: bytes; fingerprint: str
_VIEWS: weakref.WeakKeyDictionary[VerifiedMatrixView, _State] = weakref.WeakKeyDictionary()
def _public(value: VerifiedMatrixView) -> tuple[object, ...]: return (value.envelope_sha256, value.platform_qualified_subject_envelope_sha256, value.normalized_platform_mapping_payload_sha256, value.normalized_platform_mapping_payload_bytes)
def _same_public(view: VerifiedMatrixView, state: _State) -> bool:
    current = _public(view)
    return view._canonical_source_bytes is state.source and len(current) == len(state.public) and all(value is expected for value, expected in zip(current, state.public))
def _serialize(value: object) -> object:
    if type(value) in {str, int} or value is None: return value
    if type(value) is bytes: return _sha(value)
    if type(value) is tuple: return [_serialize(item) for item in value]
    _fail("MATRIX_VERIFIED_INVALID")
def _fingerprint(fields: tuple[object, ...], source: bytes) -> str:
    return _sha(canonical_bytes({"fields": _serialize(fields), "source": _sha(source)}))


def _verify(matrix: object, subject: QualifiedSubjectView, now: object) -> tuple[tuple[object, ...], bytes]:
    from scripts.rc0_policy.qualified_subject import QualifiedSubjectView
    if type(subject) is not QualifiedSubjectView or type(now) is not int or isinstance(now, bool): _fail("MATRIX_INPUT_INVALID")
    try: subject.require_verified(now)
    except Exception as error: raise MatrixFailure("MATRIX_SUBJECT_INVALID") from error
    if type(matrix) is not VerifiedEnvelope: _fail("MATRIX_ENVELOPE_INVALID")
    try: require_fixture_verified(matrix); payload = loads_canonical(matrix.payload_canonical_bytes)
    except Exception as error: raise MatrixFailure("MATRIX_ENVELOPE_INVALID") from error
    mapping = subject._mapping
    raw = _SCHEMA_PATH.read_bytes()
    try: AdjunctSchemaStore({_SCHEMA: raw}).validate(_SCHEMA, matrix.payload_schema_sha256, payload)
    except Exception as error: raise MatrixFailure("MATRIX_ENVELOPE_INVALID") from error
    identity = PrincipalBinding(matrix.issuer_role, matrix.issuer_subject_id, matrix.issuer_controlling_account_id, matrix.issuer_delegated_session_id, matrix.issuer_lane_id)
    expected_identity = dict(mapping.adjunct_trust.role_principal_constraints).get("qualification_aggregator")
    if matrix.payload_schema_id != _SCHEMA or not _same_principal(identity, expected_identity):
        _fail("MATRIX_ENVELOPE_INVALID")
    expected = normalized_platform_mapping_payload(subject._attestations)
    digest = _sha(expected)
    if matrix.payload_schema_sha256 != _sha(raw) or matrix.payload_schema_sha256 != dict(mapping.adjunct_schema_digests).get(_SCHEMA) or matrix.payload_sha256 != _sha(matrix.payload_canonical_bytes) or not matrix.not_before_epoch_seconds <= matrix.issued_at_epoch_seconds <= now <= matrix.expires_at_epoch_seconds or payload.get("platform_qualified_subject_envelope_sha256") != subject.envelope_sha256 or payload.get("normalized_platform_mapping") != loads_canonical(expected) or payload.get("normalized_platform_mapping_payload_sha256") != digest or digest != subject.normalized_mapping_payload_sha256:
        _fail("MATRIX_BINDING_MISMATCH")
    source = matrix.envelope_canonical_bytes
    return (matrix.envelope_sha256, subject.envelope_sha256, digest, expected), source


def fixture_verify_platform_matrix(matrix: VerifiedEnvelope, subject: QualifiedSubjectView, now_epoch_seconds: int) -> VerifiedMatrixView:
    fields, source = _verify(matrix, subject, now_epoch_seconds)
    view = VerifiedMatrixView(_TOKEN, **dict(zip(("envelope_sha256", "platform_qualified_subject_envelope_sha256", "normalized_platform_mapping_payload_sha256", "normalized_platform_mapping_payload_bytes"), fields)), _matrix_envelope=matrix, _subject=subject, _canonical_source_bytes=source)
    _VIEWS[view] = _State(matrix, subject, _public(view), source, _fingerprint(fields, source))
    view.require_verified(now_epoch_seconds)
    return view


def verify_platform_matrix(*args: object, **kwargs: object) -> None:
    """Reject the superseded G1 production matrix entrypoint before parsing."""
    _fail("SUPERSEDED_G1_UNSUPPORTED")
