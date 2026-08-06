import json
from pathlib import Path

from .commands import build_sign_command, build_verify_command, bundle_target, rooted_target
from .evidence import build_development_evidence
from .identity import candidate_identity
from .models import (
    CommandResult,
    Disposition,
    ExecutionMode,
    EvidenceTarget,
    FailureCode,
    SignatureIdentity,
    SigningFailure,
    SigningOutcome,
    SigningProfile,
    SigningRequest,
    Status,
    ValidatedCandidate,
)
from .parsers import parse_codesign_result
from .policy import parse_profile
from .runner import FakeRunner, Runner
from .validation import revalidate_candidate, validate_request
from .state import CandidateStage, CandidateState, capture_next_state, initial_state


def prepare_signing(request: SigningRequest, runner: Runner, host_platform: str) -> SigningOutcome:
    profile = parse_profile(request.profile) if isinstance(request, SigningRequest) else _failure(
        FailureCode.UNKNOWN_PROFILE, "profile", request
    )
    if isinstance(profile, SigningFailure):
        return _outcome(profile.code, profile.phase, request, Disposition.REJECTED)
    if profile is SigningProfile.PRODUCTION_DEVELOPER_ID:
        if host_platform != "darwin":
            return _outcome(FailureCode.UNSUPPORTED_PLATFORM, "platform", request, Disposition.BLOCKED_PLATFORM)
        return _outcome(FailureCode.BLOCKED_CREDENTIALS, "credentials", request, Disposition.BLOCKED_CREDENTIALS)
    if request.execution_mode is not ExecutionMode.FAKE:
        return _outcome(FailureCode.PROFILE_DOWNGRADE_REJECTED, "execution-mode", request, Disposition.REJECTED)
    if type(runner) is not FakeRunner:
        return _outcome(FailureCode.PROFILE_DOWNGRADE_REJECTED, "runner", request, Disposition.REJECTED)
    validated = validate_request(request)
    if isinstance(validated, SigningFailure):
        return _outcome(validated.code, validated.phase, request, Disposition.REJECTED)
    return _prepare_development(validated, request, runner, host_platform)


def normalize_outcome(outcome: SigningOutcome) -> bytes:
    if not isinstance(outcome, SigningOutcome) or not isinstance(outcome.status, Status) or not isinstance(outcome.disposition, Disposition):
        raise ValueError("invalid signing outcome")
    failure = outcome.failure
    if failure is not None and not isinstance(failure, SigningFailure):
        raise ValueError("invalid signing outcome")
    payload = {
        "disposition": outcome.disposition.value,
        "failure": None if failure is None else {"code": failure.code.value, "phase": failure.phase, "candidate_id": failure.candidate_id},
        "status": outcome.status.value,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _prepare_development(candidate: ValidatedCandidate, request: SigningRequest, runner: Runner, host_platform: str) -> SigningOutcome:
    commands = _development_commands(candidate)
    results: list[CommandResult] = []
    state = initial_state(candidate)
    for command in commands:
        failure = revalidate_candidate(request.candidate_app, state.candidate)
        if failure:
            return _outcome(failure.code, command.phase, None, Disposition.REJECTED)
        try:
            result = runner.run(command)
        except Exception:
            return _outcome(FailureCode.UNKNOWN_STATUS, command.phase, None, Disposition.REJECTED)
        failure = parse_codesign_result(result)
        if failure is not None:
            return _outcome(failure, command.phase, None, Disposition.REJECTED)
        results.append(result)
        if command.phase == "sign-daemon":
            state = _next_state(request, CandidateStage.DAEMON_SIGNED, command.phase)
        elif command.phase == "sign-app":
            state = _next_state(request, CandidateStage.APP_SIGNED, command.phase)
        if isinstance(state, SigningOutcome):
            return state
    failure = revalidate_candidate(request.candidate_app, state.candidate)
    if failure:
        return _outcome(failure.code, "evidence", None, Disposition.REJECTED)
    try:
        evidence = build_development_evidence(
            candidate_identity(state.candidate),
            host_platform,
            EvidenceTarget(state.candidate.candidate.relative_name, state.candidate.main.relative_path, state.candidate.daemon.relative_path),
            commands,
            results,
            state.stage.value,
        )
    except (TypeError, ValueError):
        return _outcome(FailureCode.UNKNOWN_STATUS, "evidence", None, Disposition.REJECTED)
    return SigningOutcome(Status.AD_HOC_PREPARED, Disposition.DEVELOPMENT_ONLY, None, evidence)


def _development_commands(candidate: ValidatedCandidate):
    daemon = rooted_target(candidate, candidate.daemon)
    app = bundle_target(candidate)
    return (
        build_sign_command(daemon, Path("daemon.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", candidate.daemon_entitlements),
        build_verify_command(daemon, SigningProfile.DEVELOPMENT_AD_HOC),
        build_sign_command(app, Path("app.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", candidate.app_entitlements),
        build_verify_command(app, SigningProfile.DEVELOPMENT_AD_HOC),
    )


def _next_state(request: SigningRequest, stage: CandidateStage, phase: str) -> CandidateState | SigningOutcome:
    captured = capture_next_state(request, stage)
    return captured if isinstance(captured, CandidateState) else _outcome(captured.code, phase, request, Disposition.REJECTED)


def _outcome(code: FailureCode, phase: str, request: object, disposition: Disposition) -> SigningOutcome:
    return SigningOutcome(Status.BLOCKED, disposition, _failure(code, phase, request), None)


def _failure(code: FailureCode, phase: str, request: object) -> SigningFailure:
    candidate = request.candidate_app if isinstance(request, SigningRequest) else None
    candidate_id = candidate.name if isinstance(candidate, Path) else ""
    return SigningFailure(code, phase, candidate_id)
