import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from .models import EntitlementBinding, ValidatedTarget

_IDENTITY_REF = re.compile(r"[0-9A-F]{40}")
_PROFILE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


@dataclass(frozen=True)
class ProductCandidateRequest:
    candidate_app: Path
    release_candidate_sha256: str
    app_entitlements: Path
    cli_entitlements: Path
    daemon_entitlements: Path


@dataclass(frozen=True)
class ProductCandidateIdentity:
    relative_name: str
    tree_sha256: str
    main_sha256: str
    cli_sha256: str
    daemon_sha256: str
    release_candidate_sha256: str
    app_entitlements_sha256: str
    cli_entitlements_sha256: str
    daemon_entitlements_sha256: str


@dataclass(frozen=True)
class ProductValidatedCandidate:
    candidate: ProductCandidateIdentity
    main: ValidatedTarget
    cli: ValidatedTarget
    daemon: ValidatedTarget
    app_entitlements: EntitlementBinding
    cli_entitlements: EntitlementBinding
    daemon_entitlements: EntitlementBinding


@dataclass(frozen=True)
class ProductionCredentialReferences:
    signing_identity_ref: str = field(repr=False)
    notary_profile_ref: str = field(repr=False)
    notary_keychain_ref: Path = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.signing_identity_ref, str) or not _IDENTITY_REF.fullmatch(
            self.signing_identity_ref
        ):
            raise ValueError("invalid signing identity reference")
        if not isinstance(self.notary_profile_ref, str) or not _PROFILE_REF.fullmatch(
            self.notary_profile_ref
        ):
            raise ValueError("invalid notary profile reference")
        if (
            not isinstance(self.notary_keychain_ref, Path)
            or not self.notary_keychain_ref.is_absolute()
            or self.notary_keychain_ref.suffix not in (".keychain", ".keychain-db")
        ):
            raise ValueError("invalid notary keychain reference")


@dataclass(frozen=True)
class ExternalCommandTemplate:
    phase: str
    program: str
    argv: tuple[str, ...]


class ProductSigningStage(StrEnum):
    UNSIGNED_APP = "UNSIGNED_APP"
    RUNNED_SIGNED_VERIFIED = "RUNNED_SIGNED_VERIFIED"
    RUNNE_SIGNED_VERIFIED = "RUNNE_SIGNED_VERIFIED"
    APP_SIGNED_VERIFIED = "APP_SIGNED_VERIFIED"
    APP_NOTARIZED = "APP_NOTARIZED"
    APP_STAPLED_VERIFIED = "APP_STAPLED_VERIFIED"
    DMG_CREATED_VERIFIED = "DMG_CREATED_VERIFIED"
    DMG_NOTARIZED = "DMG_NOTARIZED"
    DMG_STAPLED_VERIFIED = "DMG_STAPLED_VERIFIED"
    COMPLETE = "COMPLETE"


@dataclass(frozen=True)
class ProductSigningRunRequest:
    candidate: ProductCandidateRequest
    credentials: ProductionCredentialReferences = field(repr=False)
    output_dmg: Path
    evidence_path: Path


@dataclass(frozen=True)
class ProductExecutionRecord:
    template: ExternalCommandTemplate
    outcome: str


@dataclass(frozen=True)
class ProductSigningEvidence:
    initial_candidate: ProductCandidateIdentity
    final_candidate: ProductCandidateIdentity
    dmg_relative_name: str
    dmg_sha256: str
    dmg_size: int
    commands: tuple[ProductExecutionRecord, ...]


@dataclass(frozen=True)
class ProductSigningOutcome:
    stage: ProductSigningStage
    failure: "SigningFailure | None"
    evidence: ProductSigningEvidence | None
