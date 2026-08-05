from scripts.release_v2.model import (
    ArtifactEntry,
    ArtifactInventoryV2,
    BuildInputIdentityV2,
    ProductTupleIdentityV1,
    QualificationSubjectIdentityV1,
    ReleaseCandidateIdentityV2,
    ReleaseSnapshotIdentity,
)


def validate_build_input_identity(value: object) -> None:
    _require_instance(value, BuildInputIdentityV2, "build input identity")
    _require_strings(value, ("schema_version", "source_revision", "source_tree_sha256", "release_version", "target", "platform", "toolchain", "cargo_lock_sha256", "pnpm_lock_sha256", "release_profile"))
    _require_string_tuple(value.profile_digests, "profile digests")
    _require_int(value.source_date_epoch, "source date epoch")


def validate_artifact_entry(value: object) -> None:
    _require_instance(value, ArtifactEntry, "artifact entry")
    _require_strings(value, ("path", "kind", "mode", "sha256"))
    _require_int(value.size, "artifact size")


def validate_artifact_inventory(value: object) -> None:
    _require_instance(value, ArtifactInventoryV2, "artifact inventory")
    _require_strings(value, ("schema_version", "candidate_sha256", "inventory_sha256"))
    _require_tuple_of(value.entries, ArtifactEntry, "artifact entries")


def validate_product_tuple_identity(value: object) -> None:
    _require_instance(value, ProductTupleIdentityV1, "product tuple identity")
    _require_strings(value, ("build_input_sha256", "artifact_inventory_sha256", "sbom_sha256", "license_report_sha256", "provenance_sha256", "schema_revision"))
    _require_string_tuple(value.components, "product components")


def validate_qualification_subject_identity(value: object) -> None:
    _require_instance(value, QualificationSubjectIdentityV1, "qualification subject identity")
    _require_strings(value, ("build_input_sha256", "product_tuple_sha256", "subject_sha256"))


def validate_release_candidate_identity(value: object) -> None:
    _require_instance(value, ReleaseCandidateIdentityV2, "release candidate identity")
    _require_strings(value, ("build_input_sha256", "artifact_inventory_sha256", "manifest_schema", "release_profile", "product_tuple_sha256"))
    _require_string_tuple(value.qualification_evidence_sha256s, "qualification evidence digests")


def validate_release_snapshot_identity(value: object) -> None:
    _require_instance(value, ReleaseSnapshotIdentity, "release snapshot identity")
    _require_strings(value, ("candidate_sha256", "claim_matrix_sha256", "archive_index_sha256", "snapshot_sha256"))
    _require_string_tuple(value.review_sha256s, "review digests")


def _require_instance(value: object, expected: type[object], label: str) -> None:
    if type(value) is not expected:
        raise ValueError(f"{label} must not be subclassed")


def _require_strings(value: object, fields: tuple[str, ...]) -> None:
    for field in fields:
        if type(getattr(value, field)) is not str:
            raise ValueError(f"{field} must be a string")


def _require_int(value: object, label: str) -> None:
    if type(value) is not int:
        raise ValueError(f"{label} must be an integer")


def _require_string_tuple(value: object, label: str) -> None:
    _require_tuple_of(value, str, label)


def _require_tuple_of(value: object, expected: type[object], label: str) -> None:
    if type(value) is not tuple or not all(type(item) is expected for item in value):
        raise ValueError(f"{label} must be typed")
