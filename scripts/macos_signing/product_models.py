import re
from dataclasses import dataclass, field
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

    def __post_init__(self) -> None:
        if not isinstance(self.signing_identity_ref, str) or not _IDENTITY_REF.fullmatch(
            self.signing_identity_ref
        ):
            raise ValueError("invalid signing identity reference")
        if not isinstance(self.notary_profile_ref, str) or not _PROFILE_REF.fullmatch(
            self.notary_profile_ref
        ):
            raise ValueError("invalid notary profile reference")


@dataclass(frozen=True)
class ExternalCommandTemplate:
    phase: str
    program: str
    argv: tuple[str, ...]
