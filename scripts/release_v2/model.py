from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from typing import TypeAlias


class FailureCodeV1(str, Enum):
    CANDIDATE_DIRTY = "CandidateDirty"
    CANDIDATE_IDENTITY_MISMATCH = "CandidateIdentityMismatch"
    SOURCE_REVISION_INVALID = "SourceRevisionInvalid"
    MANIFEST_INVALID = "ManifestInvalid"
    ARTIFACT_MISSING = "ArtifactMissing"
    ARTIFACT_UNEXPECTED = "ArtifactUnexpected"
    ARTIFACT_DIGEST_MISMATCH = "ArtifactDigestMismatch"
    ARTIFACT_MODE_MISMATCH = "ArtifactModeMismatch"
    PATH_UNSAFE = "PathUnsafe"
    CHECKSUM_INVALID = "ChecksumInvalid"
    SBOM_INCOMPLETE = "SbomIncomplete"
    DEPENDENCY_INVENTORY_INCOMPLETE = "DependencyInventoryIncomplete"
    LICENSE_DENIED = "LicenseDenied"
    LICENSE_EVIDENCE_MISSING = "LicenseEvidenceMissing"
    ADVISORY_BLOCKED = "AdvisoryBlocked"
    ADVISORY_REPORT_MISSING = "AdvisoryReportMissing"
    EVIDENCE_MISSING = "EvidenceMissing"
    EVIDENCE_STALE = "EvidenceStale"
    EVIDENCE_CANDIDATE_MISMATCH = "EvidenceCandidateMismatch"
    HOSTED_LANE_MISSING = "HostedLaneMissing"
    SIGNING_BLOCKED_CREDENTIALS = "SigningBlockedCredentials"
    NATIVE_SANDBOX_NOT_QUALIFIED = "NATIVE_SANDBOX_NOT_QUALIFIED"
    QUALIFICATION_NOT_RUN = "QualificationNotRun"
    CLAIM_UNSUPPORTED = "ClaimUnsupported"
    REVIEW_MISSING = "ReviewMissing"
    SELF_APPROVAL_REJECTED = "SelfApprovalRejected"
    ROLLBACK_UNSUPPORTED = "RollbackUnsupported"
    INPUT_MUTATION_DETECTED = "InputMutationDetected"
    PRODUCTION_GATE_BLOCKED = "ProductionGateBlocked"


class FailureCodeV2(str, Enum):
    HARDLINK_REJECTED = "HardlinkRejected"
    SPECIAL_FILE_REJECTED = "SpecialFileRejected"
    CASE_COLLISION_REJECTED = "CaseCollisionRejected"
    ARCHIVE_NONDETERMINISTIC = "ArchiveNondeterministic"


FailureCode: TypeAlias = FailureCodeV1 | FailureCodeV2


class ClaimDisposition(str, Enum):
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"
    BLOCKED_CREDENTIALS = "BLOCKED_CREDENTIALS"
    BLOCKED_PLATFORM = "BLOCKED_PLATFORM"
    BLOCKED_HOSTED_EVIDENCE = "BLOCKED_HOSTED_EVIDENCE"
    NOT_RUN = "NOT_RUN"
    NOT_ACTIVATED = "NOT_ACTIVATED"
    UNSUPPORTED = "UNSUPPORTED"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"


class FixtureStatus(str, Enum):
    STRUCTURAL_FIXTURE_VALID = "STRUCTURAL_FIXTURE_VALID"


class OverallStatus(str, Enum):
    BLOCKED_EVIDENCE = "BLOCKED_EVIDENCE"


class ReleaseFailure(ValueError):
    def __init__(self, code: FailureCode, detail: str) -> None:
        _require_failure_code(code)
        _require_safe_detail(detail)
        self.code = code
        self.detail = detail
        super().__init__(code.value)


@dataclass(frozen=True)
class BuildInputIdentityV2:
    schema_version: str
    source_revision: str
    source_tree_sha256: str
    release_version: str
    target: str
    platform: str
    profile_digests: tuple[str, ...]
    toolchain: str
    cargo_lock_sha256: str
    pnpm_lock_sha256: str
    release_profile: str
    source_date_epoch: int

    def __post_init__(self) -> None:
        from scripts.release_v2.model_validation import validate_build_input_identity

        validate_build_input_identity(self)


@dataclass(frozen=True)
class ArtifactEntry:
    path: str
    kind: str
    mode: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        from scripts.release_v2.model_validation import validate_artifact_entry

        validate_artifact_entry(self)


@dataclass(frozen=True)
class ArtifactInventoryV2:
    schema_version: str
    candidate_sha256: str
    entries: tuple[ArtifactEntry, ...]
    inventory_sha256: str

    def __post_init__(self) -> None:
        from scripts.release_v2.model_validation import validate_artifact_inventory

        validate_artifact_inventory(self)


@dataclass(frozen=True)
class ProductTupleIdentityV1:
    build_input_sha256: str
    artifact_inventory_sha256: str
    sbom_sha256: str
    license_report_sha256: str
    provenance_sha256: str
    components: tuple[str, ...]
    schema_revision: str

    def __post_init__(self) -> None:
        from scripts.release_v2.model_validation import validate_product_tuple_identity

        validate_product_tuple_identity(self)


@dataclass(frozen=True)
class QualificationSubjectIdentityV1:
    build_input_sha256: str
    product_tuple_sha256: str
    subject_sha256: str

    def __post_init__(self) -> None:
        from scripts.release_v2.model_validation import validate_qualification_subject_identity

        validate_qualification_subject_identity(self)


@dataclass(frozen=True)
class ReleaseCandidateIdentityV2:
    build_input_sha256: str
    artifact_inventory_sha256: str
    manifest_schema: str
    release_profile: str
    product_tuple_sha256: str
    qualification_evidence_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        from scripts.release_v2.model_validation import validate_release_candidate_identity

        validate_release_candidate_identity(self)


@dataclass(frozen=True)
class ReleaseSnapshotIdentity:
    candidate_sha256: str
    claim_matrix_sha256: str
    review_sha256s: tuple[str, ...]
    archive_index_sha256: str
    snapshot_sha256: str

    def __post_init__(self) -> None:
        from scripts.release_v2.model_validation import validate_release_snapshot_identity

        validate_release_snapshot_identity(self)


@dataclass(frozen=True)
class FailureRecordV1:
    code: FailureCode
    detail: str

    def __post_init__(self) -> None:
        _require_failure_code(self.code)
        _require_safe_detail(self.detail)


@dataclass(frozen=True)
class ClaimRecordV1:
    claim_id: str
    disposition: ClaimDisposition
    blocker_code: FailureCode | None
    subject_sha256: str

    def __post_init__(self) -> None:
        _require_exact_str(self.claim_id, "claim id")
        _require_enum(self.disposition, ClaimDisposition, "claim disposition")
        if self.blocker_code is not None:
            _require_failure_code(self.blocker_code)
        _require_exact_str(self.subject_sha256, "claim subject")


@dataclass(frozen=True)
class ProductionGateV1:
    disposition: ClaimDisposition
    failure_code: FailureCode

    def __post_init__(self) -> None:
        if self.disposition is not ClaimDisposition.BLOCKED or self.failure_code is not FailureCodeV1.PRODUCTION_GATE_BLOCKED:
            raise ValueError("production gate is blocked")


@dataclass(frozen=True)
class GateResultV1:
    schema_version: str
    overall_status: OverallStatus
    production_approved: bool
    production_gate: ProductionGateV1
    failures: tuple[FailureRecordV1, ...]
    claims: tuple[ClaimRecordV1, ...]
    fixture_status: FixtureStatus | None = None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version != "release-v2-result.v1":
            raise ValueError("result schema is invalid")
        _require_enum(self.overall_status, OverallStatus, "overall status")
        if self.overall_status is not OverallStatus.BLOCKED_EVIDENCE:
            raise ValueError("result status is blocked")
        if type(self.production_approved) is not bool or self.production_approved is not False:
            raise ValueError("production approval is unavailable in Task 10")
        if type(self.production_gate) is not ProductionGateV1:
            raise ValueError("production gate must be typed")
        if type(self.failures) is not tuple or not all(type(failure) is FailureRecordV1 for failure in self.failures):
            raise ValueError("failures must be typed records")
        if type(self.claims) is not tuple or not all(type(claim) is ClaimRecordV1 for claim in self.claims):
            raise ValueError("claims must be typed records")
        if not self.production_approved and any(claim.disposition is ClaimDisposition.VERIFIED for claim in self.claims):
            raise ValueError("unapproved result cannot contain verified claims")
        if self.fixture_status is not None and (type(self.fixture_status) is not FixtureStatus or self.fixture_status is not FixtureStatus.STRUCTURAL_FIXTURE_VALID):
            raise ValueError("fixture status is invalid")
        if self.fixture_status is not None and self.failures:
            raise ValueError("structural fixture cannot contain failures")

    def as_dict(self) -> dict[str, object]:
        result = _json_value(asdict(self))
        if self.fixture_status is None:
            del result["fixture_status"]
        return result


def _json_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    return value


def _require_failure_code(value: object) -> None:
    if type(value) not in (FailureCodeV1, FailureCodeV2):
        raise ValueError("failure code must be a recognized enum")


def _require_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if type(value) is not enum_type:
        raise ValueError(f"{label} must be a recognized enum")


def _require_exact_str(value: object, label: str) -> None:
    if type(value) is not str:
        raise ValueError(f"{label} must be a string")


def _require_safe_detail(value: object) -> None:
    forbidden = ("credential", "password", "secret", "token")
    if (
        type(value) is not str
        or not value
        or len(value) > 64
        or not value.isascii()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_ " for character in value)
        or value[0] in "_ "
        or value[-1] in "_ "
        or any(separator in value for separator in ("__", "  ", "_ ", " _"))
        or any(word in value for word in forbidden)
    ):
        raise ValueError("failure detail must be a safe machine-readable code")
