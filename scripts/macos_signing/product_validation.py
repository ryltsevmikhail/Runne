import re
import stat
from pathlib import Path

from .entitlements import entitlement_binding_is_current
from .hashing import sha256_file
from .models import FailureCode, SigningFailure, ValidatedTarget
from .product_models import (
    ProductCandidateIdentity,
    ProductCandidateRequest,
    ProductValidatedCandidate,
)
from .product_entitlements import bind_product_entitlements
from .tree import tree_sha256

_SHA256 = re.compile(r"[0-9a-f]{64}")
_EXECUTABLE_NAMES = ("runne-desktop", "runne", "runned")


def validate_product_candidate(
    request: ProductCandidateRequest,
) -> ProductValidatedCandidate | SigningFailure:
    if not isinstance(request, ProductCandidateRequest):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    if not isinstance(request.release_candidate_sha256, str) or not _SHA256.fullmatch(
        request.release_candidate_sha256
    ):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    paths = _candidate_targets(request.candidate_app)
    if paths is None:
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    if not _regular_file(
        request.candidate_app / "Contents" / "embedded.provisionprofile"
    ):
        return _failure(FailureCode.ENTITLEMENTS_MISMATCH, "provisioning-profile")
    try:
        entitlements = bind_product_entitlements(
            (
                request.app_entitlements,
                request.cli_entitlements,
                request.daemon_entitlements,
            )
        )
    except Exception:
        return _failure(FailureCode.ENTITLEMENTS_MISMATCH, "entitlements")
    try:
        main, cli, daemon = tuple(
            _target(request.candidate_app, path) for path in paths
        )
        tree_digest = tree_sha256(request.candidate_app)
    except (OSError, ValueError):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    app_binding, cli_binding, daemon_binding = entitlements
    identity = ProductCandidateIdentity(
        relative_name=request.candidate_app.name,
        tree_sha256=tree_digest,
        main_sha256=main.sha256,
        cli_sha256=cli.sha256,
        daemon_sha256=daemon.sha256,
        release_candidate_sha256=request.release_candidate_sha256,
        app_entitlements_sha256=app_binding.sha256,
        cli_entitlements_sha256=cli_binding.sha256,
        daemon_entitlements_sha256=daemon_binding.sha256,
    )
    return ProductValidatedCandidate(
        identity,
        main,
        cli,
        daemon,
        app_binding,
        cli_binding,
        daemon_binding,
    )


def revalidate_product_candidate(
    candidate_app: Path,
    captured: ProductValidatedCandidate,
) -> SigningFailure | None:
    if not isinstance(candidate_app, Path) or not isinstance(
        captured, ProductValidatedCandidate
    ):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    paths = _candidate_targets(candidate_app)
    if paths is None:
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    try:
        current = tuple(_target(candidate_app, path) for path in paths)
        tree_digest = tree_sha256(candidate_app)
    except (OSError, ValueError):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    bindings = (
        captured.app_entitlements,
        captured.cli_entitlements,
        captured.daemon_entitlements,
    )
    if (
        current != (captured.main, captured.cli, captured.daemon)
        or tree_digest != captured.candidate.tree_sha256
        or not all(entitlement_binding_is_current(binding) for binding in bindings)
    ):
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "candidate")
    return None


def _candidate_targets(candidate: object) -> tuple[Path, Path, Path] | None:
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
    expected = tuple(macos / name for name in _EXECUTABLE_NAMES)
    if set(entries) != set(expected) or not all(
        _regular_executable(path) for path in expected
    ):
        return None
    return expected


def _real_directory(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_dir()
    except (OSError, ValueError):
        return False


def _regular_executable(path: Path) -> bool:
    try:
        information = path.stat()
        return (
            not path.is_symlink()
            and stat.S_ISREG(information.st_mode)
            and bool(information.st_mode & 0o111)
        )
    except (OSError, ValueError):
        return False


def _regular_file(path: Path) -> bool:
    try:
        return not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode)
    except (OSError, ValueError):
        return False


def _target(candidate: Path, path: Path) -> ValidatedTarget:
    return ValidatedTarget(str(path.relative_to(candidate)), sha256_file(path))


def _failure(code: FailureCode, phase: str) -> SigningFailure:
    return SigningFailure(code, phase, "")
