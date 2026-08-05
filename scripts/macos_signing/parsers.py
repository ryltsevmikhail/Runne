import json

from .models import CommandResult, FailureCode

_PHASES = {
    "sign-daemon",
    "sign-app",
    "verify-daemon",
    "verify-app",
    "entitlements-daemon",
    "entitlements-app",
    "notary-submit",
    "staple-staple",
    "staple-validate",
    "gatekeeper",
}


def parse_codesign_result(result: CommandResult) -> FailureCode | None:
    return _parse(
        result,
        {
            FailureCode.TOOL_UNAVAILABLE,
            FailureCode.ARTIFACT_IDENTITY_MISMATCH,
            FailureCode.HARDENED_RUNTIME_MISSING,
            FailureCode.SIGNATURE_INVALID,
        },
    )


def parse_notary_result(result: CommandResult) -> FailureCode | None:
    if not isinstance(result, CommandResult):
        return FailureCode.UNKNOWN_STATUS
    if result.exit_code != 0:
        return _parse(result, {FailureCode.TOOL_UNAVAILABLE, FailureCode.NOTARIZATION_NOT_RUN, FailureCode.NOTARIZATION_FAILED})
    try:
        payload = json.loads(result.stdout)
        status = payload["status"] if type(payload) is dict else None
    except (TypeError, ValueError, KeyError):
        return FailureCode.UNKNOWN_STATUS
    if status == "Accepted":
        return None
    return FailureCode.NOTARIZATION_FAILED if status in {"In Progress", "Invalid", "Rejected"} else FailureCode.UNKNOWN_STATUS


def parse_stapler_result(result: CommandResult) -> FailureCode | None:
    return _parse(
        result,
        {FailureCode.TOOL_UNAVAILABLE, FailureCode.STAPLE_NOT_RUN, FailureCode.STAPLE_FAILED},
    )


def parse_spctl_result(result: CommandResult) -> FailureCode | None:
    return _parse(
        result,
        {FailureCode.TOOL_UNAVAILABLE, FailureCode.GATEKEEPER_ASSESSMENT_FAILED},
    )


def normalize_result(
    result: CommandResult,
    failure: FailureCode | None,
    phase: str,
) -> bytes:
    payload = {
        "code": failure.value if isinstance(failure, FailureCode) else None,
        "exit_code": _exit_code(result),
        "phase": phase if phase in _PHASES else "unknown",
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode() + b"\n"


def _parse(result: CommandResult, allowed: set[FailureCode]) -> FailureCode | None:
    if not isinstance(result, CommandResult):
        return FailureCode.UNKNOWN_STATUS
    if result.exit_code == 0:
        return None
    for output in (result.stdout, result.stderr):
        if isinstance(output, str):
            try:
                status = FailureCode(output.strip())
            except ValueError:
                continue
            if status in allowed:
                return status
    return FailureCode.UNKNOWN_STATUS


def _exit_code(result: CommandResult) -> int | None:
    if not isinstance(result, CommandResult) or type(result.exit_code) is not int:
        return None
    return max(-255, min(result.exit_code, 255))
