import hashlib
import plistlib
import re
import stat
from pathlib import Path

from .models import (
    CandidateIdentity,
    EntitlementBinding,
    FailureCode,
    SigningFailure,
    SigningProfile,
    SigningRequest,
    ValidatedCandidate,
    ValidatedTarget,
)
from .policy import parse_profile
from .tree import tree_sha256

_SHA256 = re.compile(r"[0-9a-f]{64}")


def validate_request(request: SigningRequest) -> ValidatedCandidate | SigningFailure:
    if not isinstance(request, SigningRequest):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    profile = parse_profile(request.profile) if isinstance(request.profile, str) else _failure(
        FailureCode.UNKNOWN_PROFILE,
        "profile",
    )
    if isinstance(profile, SigningFailure):
        return profile
    if profile is SigningProfile.PRODUCTION_DEVELOPER_ID and (
        not isinstance(request.production_bundle_id, str)
        or not request.production_bundle_id.strip()
        or request.production_bundle_id in ("dev.runne.desktop", "dev.gocode.desktop")
    ):
        return _failure(FailureCode.PROFILE_DOWNGRADE_REJECTED, "profile")
    if not isinstance(request.release_candidate_sha256, str) or not _SHA256.fullmatch(
        request.release_candidate_sha256
    ):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")

    candidate = request.candidate_app
    targets = _candidate_targets(candidate)
    if targets is None:
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    main_path, daemon_path = targets

    entitlements = validate_entitlements(
        request.app_entitlements,
        request.daemon_entitlements,
    )
    if isinstance(entitlements, SigningFailure):
        return entitlements
    app_binding, daemon_binding = entitlements
    try:
        main = _target(candidate, main_path)
        daemon_target = _target(candidate, daemon_path)
        tree_digest = tree_sha256(candidate)
    except (OSError, ValueError):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    identity = CandidateIdentity(
        relative_name=candidate.name,
        tree_sha256=tree_digest,
        main_sha256=main.sha256,
        daemon_sha256=daemon_target.sha256,
        release_candidate_sha256=request.release_candidate_sha256,
        app_entitlements_sha256=app_binding.sha256,
        daemon_entitlements_sha256=daemon_binding.sha256,
    )
    return ValidatedCandidate(identity, main, daemon_target, app_binding, daemon_binding)


def revalidate_candidate(
    candidate_app: Path,
    captured: ValidatedCandidate,
) -> SigningFailure | None:
    if not isinstance(candidate_app, Path) or not isinstance(captured, ValidatedCandidate):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    targets = _candidate_targets(candidate_app)
    if targets is None:
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    try:
        current = tuple(_target(candidate_app, path) for path in targets)
        tree_digest = tree_sha256(candidate_app)
    except (OSError, ValueError):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    bindings = (captured.app_entitlements, captured.daemon_entitlements)
    if (
        current != (captured.main, captured.daemon)
        or tree_digest != captured.candidate.tree_sha256
        or not all(_binding_is_current(binding) for binding in bindings)
    ):
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "candidate")
    return None


def validate_entitlements(
    app_path: Path,
    daemon_path: Path,
) -> tuple[EntitlementBinding, EntitlementBinding] | SigningFailure:
    try:
        app_binding = _entitlement_binding(app_path)
        daemon_binding = _entitlement_binding(daemon_path)
        if (app_binding.device, app_binding.inode) == (daemon_binding.device, daemon_binding.inode):
            raise ValueError
    except Exception:
        return _failure(FailureCode.ENTITLEMENTS_MISMATCH, "entitlements")
    return app_binding, daemon_binding


def _real_directory(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_dir()
    except (OSError, ValueError):
        return False


def _candidate_targets(candidate: object) -> tuple[Path, Path] | None:
    if not isinstance(candidate, Path) or candidate.suffix != ".app":
        return None
    contents = candidate / "Contents"
    macos = contents / "MacOS"
    if not all(_real_directory(path) for path in (candidate, contents, macos)):
        return None
    try:
        entries = tuple(macos.iterdir())
    except (OSError, ValueError):
        return None
    if len(entries) != 2 or not all(_regular_executable(entry) for entry in entries):
        return None
    daemon = macos / "runned"
    main_entries = tuple(entry for entry in entries if entry.name != "runned")
    if daemon not in entries or len(main_entries) != 1:
        return None
    return main_entries[0], daemon


def _regular_executable(path: Path) -> bool:
    try:
        return (
            not path.is_symlink()
            and stat.S_ISREG(path.stat().st_mode)
            and bool(path.stat().st_mode & 0o111)
        )
    except (OSError, ValueError):
        return False


def _target(candidate: Path, path: Path) -> ValidatedTarget:
    return ValidatedTarget(str(path.relative_to(candidate)), _sha256(path.read_bytes()))


def _entitlement_binding(path: Path) -> EntitlementBinding:
    if not isinstance(path, Path) or path.is_symlink():
        raise ValueError("invalid entitlement path")
    canonical = path.resolve(strict=True)
    information = canonical.lstat()
    if canonical.is_symlink() or not stat.S_ISREG(information.st_mode):
        raise ValueError("invalid entitlement file")
    value = canonical.read_bytes()
    if type(plistlib.loads(value)) is not dict or plistlib.loads(value) != {}:
        raise ValueError("invalid entitlement plist")
    return EntitlementBinding(canonical, _sha256(value), information.st_dev, information.st_ino)


def _binding_is_current(binding: EntitlementBinding) -> bool:
    try:
        return _entitlement_binding(binding.canonical_path) == binding
    except (OSError, ValueError, plistlib.InvalidFileException):
        return False


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _failure(code: FailureCode, phase: str) -> SigningFailure:
    return SigningFailure(code, phase, "")
