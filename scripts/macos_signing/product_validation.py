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
from scripts.macos.validate_credential_service_package import (
    validate_credential_service_package,
)

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
    package = validate_credential_service_package(request.candidate_app)
    if paths is None or package is None:
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    if package.release_candidate_sha256 != request.release_candidate_sha256:
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "candidate-binding")
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
                request.credential_service_entitlements,
            )
        )
    except Exception:
        return _failure(FailureCode.ENTITLEMENTS_MISMATCH, "entitlements")
    try:
        main, cli, daemon = tuple(
            _target(request.candidate_app, path) for path in paths
        )
        credential_service = ValidatedTarget(
            str(package.helper.relative_to(request.candidate_app)),
            tree_sha256(package.helper),
        )
        tree_digest = tree_sha256(request.candidate_app)
    except (OSError, ValueError):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    app_binding, cli_binding, daemon_binding, service_binding = entitlements
    identity = ProductCandidateIdentity(
        relative_name=request.candidate_app.name,
        tree_sha256=tree_digest,
        main_sha256=main.sha256,
        cli_sha256=cli.sha256,
        daemon_sha256=daemon.sha256,
        credential_service_sha256=sha256_file(package.executable),
        launch_agent_plist_sha256=sha256_file(package.launch_agent_plist),
        credential_service_info_sha256=sha256_file(package.info_plist),
        credential_service_provisioning_sha256=sha256_file(
            package.provisioning_profile
        ),
        xpc_protocol_sha256=sha256_file(package.xpc_protocol),
        release_candidate_binding_sha256=sha256_file(
            package.release_candidate_binding
        ),
        release_candidate_sha256=request.release_candidate_sha256,
        app_entitlements_sha256=app_binding.sha256,
        cli_entitlements_sha256=cli_binding.sha256,
        daemon_entitlements_sha256=daemon_binding.sha256,
        credential_service_entitlements_sha256=service_binding.sha256,
    )
    return ProductValidatedCandidate(
        identity,
        main,
        cli,
        daemon,
        credential_service,
        app_binding,
        cli_binding,
        daemon_binding,
        service_binding,
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
    package = validate_credential_service_package(candidate_app)
    if paths is None:
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    if package is None:
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "candidate")
    try:
        current = tuple(_target(candidate_app, path) for path in paths)
        current_service = ValidatedTarget(
            str(package.helper.relative_to(candidate_app)),
            tree_sha256(package.helper),
        )
        tree_digest = tree_sha256(candidate_app)
    except (OSError, ValueError):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "candidate")
    bindings = (
        captured.app_entitlements,
        captured.cli_entitlements,
        captured.daemon_entitlements,
        captured.credential_service_entitlements,
    )
    if (
        current != (captured.main, captured.cli, captured.daemon)
        or current_service != captured.credential_service
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
