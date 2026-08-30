from dataclasses import dataclass
from pathlib import Path

from .models import EntitlementBinding, ValidatedTarget


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
