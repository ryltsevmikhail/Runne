"""Canonical, non-self-referential metadata for structural fixtures."""

import hashlib
from dataclasses import asdict

from scripts.release_v2.archive import ArchiveIndexV1
from scripts.release_v2.canonical import canonical_json, parse_canonical_json, validate_sha256
from scripts.release_v2.claims import ClaimMatrixV1, fixture_gate_result
from scripts.release_v2.model import (
    ArtifactInventoryV2,
    BuildInputIdentityV2,
    FailureCodeV1,
    ReleaseFailure,
    ReleaseSnapshotIdentity,
)


_NAMES = frozenset((
    "fixture-result.v1.json", "provenance.v1.json", "release-snapshot.v1.json",
))
_PROVENANCE_FIELDS = frozenset((
    "artifact_inventory_sha256", "build_input_sha256", "candidate_sha256", "kind",
    "schema_version", "source_revision", "source_tree_sha256",
))
_RESULT_FIELDS = frozenset((
    "claims", "failures", "fixture_status", "overall_status", "production_approved",
    "production_gate", "schema_version",
))
_SNAPSHOT_FIELDS = frozenset((
    "archive_index_sha256", "candidate_sha256", "claim_matrix_sha256",
    "review_sha256s", "snapshot_sha256",
))


def render_provenance(build: BuildInputIdentityV2, inventory: ArtifactInventoryV2) -> bytes:
    """Render provenance before its digest binds the product tuple."""
    _inputs(build, inventory)
    return canonical_json({
        "artifact_inventory_sha256": inventory.inventory_sha256,
        "build_input_sha256": _digest(canonical_json(asdict(build))),
        "candidate_sha256": inventory.candidate_sha256,
        "kind": "structural_fixture",
        "schema_version": "provenance.v1",
        "source_revision": build.source_revision,
        "source_tree_sha256": build.source_tree_sha256,
    })


def render_fixture_metadata(
    build: BuildInputIdentityV2,
    inventory: ArtifactInventoryV2,
    claims: ClaimMatrixV1,
    candidate_sha256: str,
    reviews: tuple[str, ...],
    archive_index: ArchiveIndexV1,
) -> dict[str, bytes]:
    """Render all detached metadata from already validated release inputs."""
    _inputs(build, inventory)
    if type(claims) is not ClaimMatrixV1 or type(archive_index) is not ArchiveIndexV1:
        raise _invalid()
    validate_sha256(candidate_sha256)
    if type(reviews) is not tuple or any(type(value) is not str for value in reviews):
        raise _invalid()
    for review in reviews:
        validate_sha256(review)
    claims_raw = _claims(claims)
    archive_raw = canonical_json(archive_index.as_dict())
    snapshot = _snapshot(candidate_sha256, claims_raw, reviews, archive_raw)
    return {
        "fixture-result.v1.json": canonical_json(fixture_gate_result(claims).as_dict()),
        "provenance.v1.json": render_provenance(build, inventory),
        "release-snapshot.v1.json": canonical_json(asdict(snapshot)),
    }


def parse_fixture_metadata(
    raw: dict[str, bytes],
    build: BuildInputIdentityV2,
    inventory: ArtifactInventoryV2,
    claims: ClaimMatrixV1,
    candidate_sha256: str,
    reviews: tuple[str, ...],
    archive_index: ArchiveIndexV1,
) -> dict[str, bytes]:
    """Closed-parse and exact-bind all fixture metadata bytes."""
    expected = render_fixture_metadata(
        build, inventory, claims, candidate_sha256, reviews, archive_index
    )
    if type(raw) is not dict or frozenset(raw) != _NAMES:
        raise _invalid()
    fields = {
        "fixture-result.v1.json": _RESULT_FIELDS,
        "provenance.v1.json": _PROVENANCE_FIELDS,
        "release-snapshot.v1.json": _SNAPSHOT_FIELDS,
    }
    for name, expected_raw in expected.items():
        supplied = raw[name]
        if type(supplied) is not bytes:
            raise _invalid()
        parse_canonical_json(supplied, required=fields[name], optional=frozenset())
        if supplied != expected_raw:
            raise _invalid()
    return expected


def _claims(value: ClaimMatrixV1) -> bytes:
    return canonical_json({
        "claims": [
            {
                "blocker_code": None if claim.blocker_code is None else claim.blocker_code.value,
                "claim_id": claim.claim_id,
                "disposition": claim.disposition.value,
                "subject_sha256": claim.subject_sha256,
            }
            for claim in value.claims
        ],
        "schema_version": "release-claim-matrix.v1",
        "subject_sha256": value.subject_sha256,
    })


def _snapshot(
    candidate_sha256: str, claims_raw: bytes, reviews: tuple[str, ...], archive_raw: bytes
) -> ReleaseSnapshotIdentity:
    payload = {
        "archive_index_sha256": _digest(archive_raw),
        "candidate_sha256": candidate_sha256,
        "claim_matrix_sha256": _digest(claims_raw),
        "review_sha256s": list(reviews),
    }
    return ReleaseSnapshotIdentity(
        candidate_sha256,
        payload["claim_matrix_sha256"],
        reviews,
        payload["archive_index_sha256"],
        _digest(canonical_json(payload)),
    )


def _inputs(build: object, inventory: object) -> None:
    if type(build) is not BuildInputIdentityV2 or type(inventory) is not ArtifactInventoryV2:
        raise _invalid()
    for value in (inventory.candidate_sha256, inventory.inventory_sha256):
        validate_sha256(value)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _invalid() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "fixture_metadata_invalid")
