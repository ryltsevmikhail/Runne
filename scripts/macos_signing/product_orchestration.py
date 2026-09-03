import stat
from pathlib import Path
from typing import Protocol

from .hashing import sha256_file
from .models import CommandResult, CommandSpec, FailureCode, SigningFailure
from .product_commands import (
    build_product_distribution_commands,
    build_product_signing_commands,
    redact_external_command,
)
from .product_evidence import normalize_product_evidence
from .product_layout import (
    APP_ZIP_RELATIVE,
    DMG_RELATIVE,
    staged_app_relative,
)
from .product_models import (
    ProductExecutionRecord,
    ProductSigningEvidence,
    ProductSigningOutcome,
    ProductSigningRunRequest,
    ProductSigningStage,
    ProductValidatedCandidate,
)
from .product_validation import (
    revalidate_product_candidate,
    validate_product_candidate,
)
from .product_verification import verify_product_command_result
from .product_workspace import (
    PrivateWorkspace,
    cleanup_workspace,
    create_private_workspace,
    publish_workspace,
    regular_external_file,
    validate_publication_target,
    workspace_is_current,
)
from .tree import tree_sha256


class ProductRunner(Protocol):
    def run(self, command: CommandSpec) -> CommandResult: ...


def run_product_signing(
    request: ProductSigningRunRequest,
    runner: ProductRunner,
    host_platform: str,
) -> ProductSigningOutcome:
    preflight = _preflight(request, host_platform)
    if isinstance(preflight, SigningFailure):
        return _outcome(ProductSigningStage.UNSIGNED_APP, preflight)
    candidate, publication = preflight
    root = publication.root
    state = ProductSigningStage.UNSIGNED_APP
    workspace = None
    try:
        workspace = create_private_workspace(root)
        initial = candidate.candidate
        records = []
        for command in build_product_signing_commands(candidate, request.credentials):
            failure = _before_command(request, candidate, workspace)
            if failure:
                return _failed(state, command.phase, failure.code, workspace)
            result = _run(runner, command)
            failure_code = verify_product_command_result(command, result)
            if failure_code:
                return _failed(state, command.phase, failure_code, workspace)
            records.append(_record(command))
            if command.phase.startswith("sign-"):
                captured = validate_product_candidate(request.candidate)
                if not isinstance(captured, ProductValidatedCandidate) or not _sign_changed(
                    command.phase, candidate, captured
                ):
                    return _failed(
                        state,
                        command.phase,
                        FailureCode.ARTIFACT_IDENTITY_MISMATCH,
                        workspace,
                    )
                candidate = captured
            state = _component_stage(command.phase, state)

        distribution = build_product_distribution_commands(
            candidate,
            request.credentials,
            APP_ZIP_RELATIVE,
            DMG_RELATIVE,
        )
        app_notary_digest = None
        dmg_digest = None
        for command in distribution:
            failure = _before_command(request, candidate, workspace)
            if failure:
                return _failed(state, command.phase, failure.code, workspace)
            if command.phase == "notary-app-submit" and _regular_digest(
                root / APP_ZIP_RELATIVE
            ) != app_notary_digest:
                return _failed(
                    state,
                    command.phase,
                    FailureCode.ARTIFACT_IDENTITY_MISMATCH,
                    workspace,
                )
            if command.phase == "notary-dmg-submit" and _regular_digest(
                root / DMG_RELATIVE
            ) != dmg_digest:
                return _failed(
                    state,
                    command.phase,
                    FailureCode.ARTIFACT_IDENTITY_MISMATCH,
                    workspace,
                )
            result = _run(runner, command)
            failure_code = verify_product_command_result(command, result)
            if failure_code:
                return _failed(state, command.phase, failure_code, workspace)
            records.append(_record(command))
            if command.phase == "package-app-zip":
                app_notary_digest = _regular_digest(root / APP_ZIP_RELATIVE)
            elif command.phase == "staple-app":
                captured = validate_product_candidate(request.candidate)
                if not isinstance(captured, ProductValidatedCandidate) or (
                    captured.candidate.tree_sha256 == candidate.candidate.tree_sha256
                ):
                    return _failed(
                        state,
                        command.phase,
                        FailureCode.ARTIFACT_IDENTITY_MISMATCH,
                        workspace,
                    )
                candidate = captured
            elif command.phase == "stage-dmg-app":
                if not _staged_app_matches(root, candidate):
                    return _failed(
                        state,
                        command.phase,
                        FailureCode.ARTIFACT_IDENTITY_MISMATCH,
                        workspace,
                    )
            elif command.phase == "create-dmg":
                dmg_digest = _regular_digest(root / DMG_RELATIVE)
            elif command.phase in ("sign-dmg", "staple-dmg"):
                changed = _regular_digest(root / DMG_RELATIVE)
                if changed == dmg_digest:
                    return _failed(
                        state,
                        command.phase,
                        FailureCode.ARTIFACT_IDENTITY_MISMATCH,
                        workspace,
                    )
                dmg_digest = changed
            state = _distribution_stage(command.phase, state)
        return _publish(publication, initial, candidate, records, workspace)
    except (OSError, TypeError, ValueError):
        return _failed(state, "orchestration", FailureCode.UNKNOWN_STATUS, workspace)


def _preflight(request, host_platform):
    if host_platform != "darwin":
        return _failure(FailureCode.UNSUPPORTED_PLATFORM, "platform")
    if not isinstance(request, ProductSigningRunRequest):
        return _failure(FailureCode.ARTIFACT_NOT_FOUND, "request")
    candidate = validate_product_candidate(request.candidate)
    if not isinstance(candidate, ProductValidatedCandidate):
        return candidate
    try:
        root = request.candidate.candidate_app.parent.resolve(strict=True)
    except (OSError, TypeError, ValueError):
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "output")
    publication = validate_publication_target(
        root,
        request.output_dmg,
        request.evidence_path,
    )
    if publication is None:
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "output")
    if not regular_external_file(request.credentials.notary_keychain_ref):
        return _failure(FailureCode.BLOCKED_CREDENTIALS, "notary-keychain")
    return candidate, publication


def _before_command(request, candidate, workspace):
    if not workspace_is_current(workspace):
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "workspace")
    return revalidate_product_candidate(request.candidate.candidate_app, candidate)


def _run(runner: ProductRunner, command: CommandSpec) -> CommandResult:
    try:
        result = runner.run(command)
    except Exception:
        return CommandResult(127, "", FailureCode.UNKNOWN_STATUS.value)
    return (
        result
        if isinstance(result, CommandResult)
        else CommandResult(127, "", FailureCode.UNKNOWN_STATUS.value)
    )


def _record(command: CommandSpec) -> ProductExecutionRecord:
    return ProductExecutionRecord(redact_external_command(command), "success")


def _sign_changed(phase: str, before, after) -> bool:
    role = phase.removeprefix("sign-")
    if role == "daemon":
        return before.daemon.sha256 != after.daemon.sha256
    if role == "credential-service":
        return before.credential_service.sha256 != after.credential_service.sha256
    if role == "cli":
        return before.cli.sha256 != after.cli.sha256
    return role == "app" and before.candidate.tree_sha256 != after.candidate.tree_sha256


def _regular_digest(path: Path) -> str:
    information = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(information.st_mode):
        raise ValueError("invalid product artifact")
    return sha256_file(path)


def _staged_app_matches(root: Path, candidate: ProductValidatedCandidate) -> bool:
    staged = root / staged_app_relative(candidate.candidate.relative_name)
    try:
        return (
            staged.is_dir()
            and not staged.is_symlink()
            and tree_sha256(staged) == candidate.candidate.tree_sha256
        )
    except (OSError, ValueError):
        return False


def _publish(publication, initial, candidate, records, workspace):
    dmg = publication.root / DMG_RELATIVE
    evidence = ProductSigningEvidence(
        initial,
        candidate.candidate,
        publication.output_dmg.name,
        _regular_digest(dmg),
        dmg.stat().st_size,
        tuple(records),
    )
    publish_workspace(workspace, publication, normalize_product_evidence(evidence))
    return ProductSigningOutcome(ProductSigningStage.COMPLETE, None, evidence)


def _component_stage(phase, current):
    return {
        "entitlements-credential-service": ProductSigningStage.CREDENTIAL_SERVICE_SIGNED_VERIFIED,
        "entitlements-daemon": ProductSigningStage.RUNNED_SIGNED_VERIFIED,
        "entitlements-cli": ProductSigningStage.RUNNE_SIGNED_VERIFIED,
        "entitlements-app": ProductSigningStage.APP_SIGNED_VERIFIED,
    }.get(phase, current)


def _distribution_stage(phase, current):
    return {
        "notary-app-submit": ProductSigningStage.APP_NOTARIZED,
        "validate-app": ProductSigningStage.APP_STAPLED_VERIFIED,
        "create-dmg": ProductSigningStage.DMG_CREATED_VERIFIED,
        "notary-dmg-submit": ProductSigningStage.DMG_NOTARIZED,
        "validate-dmg": ProductSigningStage.DMG_STAPLED_VERIFIED,
    }.get(phase, current)


def _failed(stage, phase, code, workspace: PrivateWorkspace | None):
    cleanup_workspace(workspace)
    return _outcome(stage, _failure(code, phase))


def _failure(code: FailureCode, phase: str) -> SigningFailure:
    return SigningFailure(code, phase, "")


def _outcome(stage, failure):
    return ProductSigningOutcome(stage, failure, None)
