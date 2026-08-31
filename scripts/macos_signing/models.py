from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class SigningProfile(StrEnum):
    DEVELOPMENT_AD_HOC = "development-ad-hoc"
    PRODUCTION_DEVELOPER_ID = "production-developer-id"


class ExecutionMode(StrEnum):
    FAKE = "fake"
    LIVE = "live"


class FailureCode(StrEnum):
    BLOCKED_CREDENTIALS = "BLOCKED_CREDENTIALS"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    SIGNING_IDENTITY_UNAVAILABLE = "SIGNING_IDENTITY_UNAVAILABLE"
    ARTIFACT_NOT_FOUND = "ARTIFACT_NOT_FOUND"
    ARTIFACT_IDENTITY_MISMATCH = "ARTIFACT_IDENTITY_MISMATCH"
    ENTITLEMENTS_MISMATCH = "ENTITLEMENTS_MISMATCH"
    HARDENED_RUNTIME_MISSING = "HARDENED_RUNTIME_MISSING"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    NOTARIZATION_NOT_RUN = "NOTARIZATION_NOT_RUN"
    NOTARIZATION_FAILED = "NOTARIZATION_FAILED"
    STAPLE_NOT_RUN = "STAPLE_NOT_RUN"
    STAPLE_FAILED = "STAPLE_FAILED"
    GATEKEEPER_ASSESSMENT_FAILED = "GATEKEEPER_ASSESSMENT_FAILED"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    EVIDENCE_SECRET_MARKER = "EVIDENCE_SECRET_MARKER"
    SYNTHETIC_EVIDENCE_REJECTED = "SYNTHETIC_EVIDENCE_REJECTED"
    EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"
    PROFILE_DOWNGRADE_REJECTED = "PROFILE_DOWNGRADE_REJECTED"
    UNKNOWN_PROFILE = "UNKNOWN_PROFILE"
    UNKNOWN_STATUS = "UNKNOWN_STATUS"


class Status(StrEnum):
    AD_HOC_PREPARED = "AD_HOC_PREPARED"
    DEVELOPMENT_ONLY = "DEVELOPMENT_ONLY"
    BLOCKED = "BLOCKED"


class Disposition(StrEnum):
    DEVELOPMENT_ONLY = "DEVELOPMENT_ONLY"
    BLOCKED_CREDENTIALS = "BLOCKED_CREDENTIALS"
    BLOCKED_PLATFORM = "BLOCKED_PLATFORM"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class SigningRequest:
    profile: SigningProfile | str
    candidate_app: Path
    production_bundle_id: str | None
    app_entitlements: Path
    daemon_entitlements: Path
    execution_mode: ExecutionMode
    keychain_profile_ref: str | None
    release_candidate_sha256: str


@dataclass(frozen=True)
class CommandSpec:
    phase: str
    program: str
    argv: tuple[str, ...]
    candidate_relative_cwd: str
    entitlement: "EntitlementBinding | None" = None
    notarization_artifact: "NotarizationArtifactBinding | None" = None

    def __post_init__(self) -> None:
        from .policy import command_arguments_are_safe, program_is_allowed

        if (
            not isinstance(self.argv, tuple)
            or not all(isinstance(item, str) for item in self.argv)
            or not program_is_allowed(self.program)
            or not command_arguments_are_safe(
                self.argv,
                ("--keychain",)
                if self.phase in ("notary-app-submit", "notary-dmg-submit")
                else (),
            )
        ):
            raise ValueError("invalid command specification")
        if self.entitlement is not None and not isinstance(self.entitlement, EntitlementBinding):
            raise ValueError("invalid entitlement binding")
        if self.notarization_artifact is not None:
            from .state import NotarizationArtifactBinding

            if not isinstance(self.notarization_artifact, NotarizationArtifactBinding):
                raise ValueError("invalid notarization artifact binding")


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class SigningFailure:
    code: FailureCode
    phase: str
    candidate_id: str


@dataclass(frozen=True)
class ValidatedTarget:
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class CandidateIdentity:
    relative_name: str
    tree_sha256: str
    main_sha256: str
    daemon_sha256: str
    release_candidate_sha256: str
    app_entitlements_sha256: str
    daemon_entitlements_sha256: str


@dataclass(frozen=True)
class EntitlementBinding:
    canonical_path: Path
    sha256: str
    device: int
    inode: int

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.canonical_path, Path) or not self.canonical_path.is_absolute() or self.canonical_path.resolve(strict=True) != self.canonical_path:
                raise ValueError("invalid entitlement binding")
        except (OSError, ValueError):
            raise ValueError("invalid entitlement binding") from None


@dataclass(frozen=True)
class ValidatedCandidate:
    candidate: CandidateIdentity
    main: ValidatedTarget
    daemon: ValidatedTarget
    app_entitlements: EntitlementBinding
    daemon_entitlements: EntitlementBinding


@dataclass(frozen=True)
class SignatureIdentity:
    bundle_id: str
    team_identifier: str
    authority_class: str
    designated_requirement: str
    cdhash: str | None


@dataclass(frozen=True)
class SignatureExpectation:
    bundle_id: str
    team_identifier: str
    authority_class: str
    designated_requirement: str
    cdhash: str | None


@dataclass(frozen=True)
class EvidenceDispositions:
    notarization: str
    stapling: str
    gatekeeper: str


@dataclass(frozen=True)
class EvidenceTarget:
    candidate: str
    main: str
    daemon: str


@dataclass(frozen=True)
class ExecutionRecord:
    phase: str
    operation: str
    target: str
    hardened_runtime: bool
    entitlement_sha256: str | None
    outcome: str


@dataclass(frozen=True)
class EvidenceCandidate:
    identity: CandidateIdentity
    signature: SignatureIdentity


@dataclass(frozen=True)
class EvidenceEntitlements:
    app_sha256: str
    daemon_sha256: str


@dataclass(frozen=True)
class SigningEvidence:
    schema_version: str
    candidate: EvidenceCandidate
    profile: SigningProfile
    platform: str
    target: EvidenceTarget
    entitlements: EvidenceEntitlements
    commands: tuple[ExecutionRecord, ...]
    notarization: str
    stapling: str
    gatekeeper: str
    disposition: str
    snapshot_stage: str = ""


@dataclass(frozen=True)
class SigningOutcome:
    status: Status
    disposition: Disposition
    failure: SigningFailure | None
    evidence: SigningEvidence | None
