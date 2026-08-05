from dataclasses import dataclass

from scripts.release_v2.canonical import validate_sha256
from scripts.release_v2.model import (
    ClaimDisposition,
    ClaimRecordV1,
    FailureCodeV1,
    FailureRecordV1,
    FixtureStatus,
    GateResultV1,
    OverallStatus,
    ProductionGateV1,
    ReleaseFailure,
)


_CURRENT = (
    ("operational_telemetry", ClaimDisposition.BLOCKED, FailureCodeV1.EVIDENCE_MISSING),
    ("macos_developer_id_signing", ClaimDisposition.BLOCKED_CREDENTIALS, FailureCodeV1.SIGNING_BLOCKED_CREDENTIALS),
    ("notarization_stapling", ClaimDisposition.BLOCKED_CREDENTIALS, FailureCodeV1.SIGNING_BLOCKED_CREDENTIALS),
    ("live_openai_l4", ClaimDisposition.NOT_RUN, None),
    ("tool_process_execution", ClaimDisposition.BLOCKED, FailureCodeV1.NATIVE_SANDBOX_NOT_QUALIFIED),
    ("mcp_fixture_mode", ClaimDisposition.BLOCKED, FailureCodeV1.EVIDENCE_MISSING),
    ("mcp_external_activation", ClaimDisposition.NOT_ACTIVATED, None),
    ("bundled_runtime", ClaimDisposition.NOT_ACTIVATED, FailureCodeV1.ARTIFACT_MISSING),
    ("external_daemon", ClaimDisposition.NOT_RUN, None),
    ("v1_v2_compatibility", ClaimDisposition.BLOCKED, FailureCodeV1.EVIDENCE_MISSING),
    ("recovery_upgrade", ClaimDisposition.NOT_RUN, None),
    ("install_upgrade_rollback", ClaimDisposition.NOT_RUN, None),
    ("linux_qualification", ClaimDisposition.BLOCKED_HOSTED_EVIDENCE, FailureCodeV1.HOSTED_LANE_MISSING),
    ("macos_qualification", ClaimDisposition.BLOCKED_HOSTED_EVIDENCE, FailureCodeV1.HOSTED_LANE_MISSING),
    ("windows_qualification", ClaimDisposition.BLOCKED_HOSTED_EVIDENCE, FailureCodeV1.HOSTED_LANE_MISSING),
    ("pinned_lane", ClaimDisposition.BLOCKED_HOSTED_EVIDENCE, FailureCodeV1.HOSTED_LANE_MISSING),
    ("msrv_lane", ClaimDisposition.BLOCKED_HOSTED_EVIDENCE, FailureCodeV1.HOSTED_LANE_MISSING),
    ("dependency_inventory", ClaimDisposition.BLOCKED, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE),
    ("license", ClaimDisposition.BLOCKED, FailureCodeV1.LICENSE_EVIDENCE_MISSING),
    ("advisory", ClaimDisposition.BLOCKED, FailureCodeV1.ADVISORY_REPORT_MISSING),
    ("sbom", ClaimDisposition.BLOCKED, FailureCodeV1.SBOM_INCOMPLETE),
    ("checksums", ClaimDisposition.BLOCKED, FailureCodeV1.ARTIFACT_MISSING),
)


@dataclass(frozen=True, slots=True)
class ClaimMatrixV1:
    subject_sha256: str
    claims: tuple[ClaimRecordV1, ...]

    def __post_init__(self) -> None:
        validate_claim_matrix(self.claims, self.subject_sha256)


def current_claim_matrix(subject_sha256: str) -> ClaimMatrixV1:
    validate_sha256(subject_sha256)
    claims = tuple(ClaimRecordV1(claim_id, disposition, blocker_code, subject_sha256) for claim_id, disposition, blocker_code in _CURRENT)
    return ClaimMatrixV1(subject_sha256, claims)


def validate_claim_matrix(claims: tuple[ClaimRecordV1, ...], subject_sha256: str) -> None:
    if type(claims) is not tuple:
        raise _invalid()
    try:
        validate_sha256(subject_sha256)
    except ReleaseFailure as error:
        raise _invalid() from error
    if len(claims) != len(_CURRENT):
        raise _invalid()
    for claim, expected in zip(claims, _CURRENT, strict=True):
        if type(claim) is not ClaimRecordV1 or (claim.claim_id, claim.disposition, claim.blocker_code, claim.subject_sha256) != (*expected, subject_sha256):
            raise _invalid()


def fixture_gate_result(matrix: ClaimMatrixV1) -> GateResultV1:
    _matrix(matrix)
    return GateResultV1(
        "release-v2-result.v1",
        OverallStatus.BLOCKED_EVIDENCE,
        False,
        ProductionGateV1(ClaimDisposition.BLOCKED, FailureCodeV1.PRODUCTION_GATE_BLOCKED),
        (),
        matrix.claims,
        FixtureStatus.STRUCTURAL_FIXTURE_VALID,
    )


def production_gate_result(matrix: ClaimMatrixV1) -> GateResultV1:
    fixture = fixture_gate_result(matrix)
    return GateResultV1(
        fixture.schema_version,
        fixture.overall_status,
        fixture.production_approved,
        fixture.production_gate,
        fixture.failures,
        fixture.claims,
    )


def production_gate_exit_code(result: GateResultV1) -> int:
    if type(result) is not GateResultV1 or result.production_approved or result.production_gate.disposition is not ClaimDisposition.BLOCKED:
        raise _invalid()
    return 1


def _matrix(value: object) -> None:
    if type(value) is not ClaimMatrixV1:
        raise _invalid()
    validate_claim_matrix(value.claims, value.subject_sha256)


def _invalid() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.CLAIM_UNSUPPORTED, "claim_matrix_invalid")
