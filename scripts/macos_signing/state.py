import hashlib
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .models import CandidateIdentity, FailureCode, SigningFailure, ValidatedCandidate
from .tree import tree_sha256
from .validation import validate_request


class CandidateStage(StrEnum):
    INITIAL = "INITIAL"
    DAEMON_SIGNED = "DAEMON_SIGNED"
    APP_SIGNED = "APP_SIGNED"
    STAPLED = "STAPLED"


@dataclass(frozen=True)
class CandidateState:
    candidate: ValidatedCandidate
    stage: CandidateStage


@dataclass(frozen=True)
class NotarizationArtifactBinding:
    canonical_path: Path
    relative_path: str
    sha256: str
    device: int
    inode: int
    source_identity: CandidateIdentity


def initial_state(candidate: ValidatedCandidate) -> CandidateState:
    return CandidateState(candidate, CandidateStage.INITIAL)


def capture_next_state(request, stage: CandidateStage) -> CandidateState | SigningFailure:
    candidate = validate_request(request)
    if isinstance(candidate, SigningFailure):
        return candidate
    return CandidateState(candidate, stage)


def bind_notarization_artifact(root: Path, relative_path: str, state: CandidateState) -> NotarizationArtifactBinding | SigningFailure:
    try:
        relative = Path(relative_path)
        if (not isinstance(state, CandidateState) or state.stage is not CandidateStage.APP_SIGNED
                or not isinstance(root, Path) or not isinstance(relative_path, str) or relative.suffix != ".zip"
                or len(relative.parts) != 1 or relative.is_absolute()):
            raise ValueError
        canonical_root = root.resolve(strict=True)
        path = canonical_root / relative_path
        canonical = path.resolve(strict=True)
        canonical.relative_to(canonical_root)
        info = canonical.lstat()
        if path.is_symlink() or canonical.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError
        return NotarizationArtifactBinding(canonical, relative_path, _digest(canonical), info.st_dev, info.st_ino, state.candidate.candidate)
    except (OSError, ValueError):
        return SigningFailure(FailureCode.ARTIFACT_NOT_FOUND, "notary-submit", "")


def artifact_is_current(binding: NotarizationArtifactBinding, root: Path, identity: CandidateIdentity) -> bool:
    try:
        if (not isinstance(binding, NotarizationArtifactBinding) or binding.source_identity != identity
                or not _source_is_current(root, identity)):
            return False
        canonical_root = root.resolve(strict=True)
        path = canonical_root / binding.relative_path
        canonical = path.resolve(strict=True)
        canonical.relative_to(canonical_root)
        info = canonical.lstat()
        return (canonical == binding.canonical_path and not path.is_symlink() and not canonical.is_symlink()
                and stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == (binding.device, binding.inode)
                and _digest(canonical) == binding.sha256)
    except (OSError, ValueError):
        return False


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_is_current(root: Path, identity: CandidateIdentity) -> bool:
    try:
        candidate = root / identity.relative_name
        main = candidate / "Contents" / "MacOS"
        daemon = main / "gocoded"
        executables = tuple(path for path in main.iterdir() if path.name != "gocoded")
        return (len(executables) == 1 and _digest(executables[0]) == identity.main_sha256
                and _digest(daemon) == identity.daemon_sha256 and tree_sha256(candidate) == identity.tree_sha256)
    except (OSError, ValueError):
        return False
