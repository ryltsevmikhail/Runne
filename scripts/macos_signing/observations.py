import plistlib
import re
from dataclasses import dataclass

from .models import CommandResult, FailureCode, SignatureExpectation, SignatureIdentity
from .parsers import parse_codesign_result
from .policy import MAX_CAPTURED_OUTPUT_BYTES

_CDHASH = re.compile(r"[0-9A-Fa-f]{40}")
_FLAGS = re.compile(r"flags=0x([0-9a-fA-F]+)\(([^()\s]+)\)")


@dataclass(frozen=True)
class _CheckedObservationBundle:
    daemon: SignatureIdentity
    app: SignatureIdentity
    daemon_runtime: bool
    app_runtime: bool


def parse_signature_metadata(result: CommandResult) -> SignatureIdentity | FailureCode:
    failed = _failed(result)
    if failed:
        return failed
    lines = _lines(result)
    if lines is None:
        return FailureCode.UNKNOWN_STATUS
    values: dict[str, str] = {}
    developer_authorities = []
    runtime = None
    for line in lines:
        if line.startswith("Authority=Developer ID Application:"):
            developer_authorities.append(line)
        for name in ("Identifier", "TeamIdentifier", "CDHash"):
            prefix = name + "="
            if line.startswith(prefix):
                if name in values:
                    return FailureCode.UNKNOWN_STATUS
                values[name] = line.removeprefix(prefix)
        if line.startswith("CodeDirectory"):
            if runtime is not None:
                return FailureCode.UNKNOWN_STATUS
            runtime = _runtime(line)
            if runtime is None:
                return FailureCode.UNKNOWN_STATUS
    if set(values) != {"Identifier", "TeamIdentifier", "CDHash"} or len(developer_authorities) != 1 or runtime is None:
        return FailureCode.UNKNOWN_STATUS
    if not all(_safe(value) for value in values.values()) or _CDHASH.fullmatch(values["CDHash"]) is None:
        return FailureCode.UNKNOWN_STATUS
    return SignatureIdentity(values["Identifier"], values["TeamIdentifier"], "Developer ID Application", "", values["CDHash"].lower()) if runtime else FailureCode.HARDENED_RUNTIME_MISSING


def _runtime(line: str) -> bool | None:
    tokens = line.split(" ")
    if len(tokens) < 3 or tokens[:2] != ["CodeDirectory", tokens[1]] or not tokens[1].startswith("v=") or not tokens[1][2:].isdigit():
        return None
    flags = [token for token in tokens[2:] if token.startswith("flags=")]
    if len(flags) != 1 or any(not token or "=" not in token for token in tokens[2:]):
        return None
    match = _FLAGS.fullmatch(flags[0])
    if match is None:
        return None
    return bool(int(match.group(1), 16) & 0x10000) and "runtime" in match.group(2).split(",")


def parse_designated_requirement(result: CommandResult) -> str | FailureCode:
    failed = _failed(result)
    if failed:
        return failed
    lines = _lines(result)
    if lines is None:
        return FailureCode.UNKNOWN_STATUS
    requirements = [line for line in lines if line.startswith("designated => ")]
    if len(requirements) != 1 or not _safe(requirements[0].removeprefix("designated => ")):
        return FailureCode.UNKNOWN_STATUS
    return requirements[0]


def parse_embedded_entitlements(result: CommandResult) -> FailureCode | None:
    failed = _failed(result)
    if failed:
        return failed
    value = result.stdout if result.stdout else result.stderr
    if not isinstance(value, str) or len(value.encode()) > MAX_CAPTURED_OUTPUT_BYTES or _control(value):
        return FailureCode.UNKNOWN_STATUS
    try:
        return None if plistlib.loads(value.encode()) == {} else FailureCode.ENTITLEMENTS_MISMATCH
    except (plistlib.InvalidFileException, ValueError):
        return FailureCode.UNKNOWN_STATUS


def _checked_observations(
    daemon: SignatureIdentity, app: SignatureIdentity, daemon_requirement: str, app_requirement: str,
    daemon_expectation: SignatureExpectation, app_expectation: SignatureExpectation,
) -> _CheckedObservationBundle | FailureCode:
    if not all(isinstance(item, SignatureIdentity) for item in (daemon, app)) or not all(isinstance(item, SignatureExpectation) for item in (daemon_expectation, app_expectation)):
        return FailureCode.UNKNOWN_STATUS
    if daemon_requirement != daemon_expectation.designated_requirement or app_requirement != app_expectation.designated_requirement:
        return FailureCode.ARTIFACT_IDENTITY_MISMATCH
    for observed, expectation in ((daemon, daemon_expectation), (app, app_expectation)):
        if (observed.bundle_id, observed.team_identifier, observed.authority_class, observed.cdhash) != (
            expectation.bundle_id, expectation.team_identifier, expectation.authority_class, expectation.cdhash
        ):
            return FailureCode.ARTIFACT_IDENTITY_MISMATCH
    return _CheckedObservationBundle(
        SignatureIdentity(daemon.bundle_id, daemon.team_identifier, daemon.authority_class, daemon_requirement, daemon.cdhash),
        SignatureIdentity(app.bundle_id, app.team_identifier, app.authority_class, app_requirement, app.cdhash),
        True,
        True,
    )


def metadata_result_failure(result: CommandResult) -> FailureCode | None:
    value = parse_signature_metadata(result)
    return value if isinstance(value, FailureCode) else None


def requirement_result_failure(result: CommandResult) -> FailureCode | None:
    value = parse_designated_requirement(result)
    return value if isinstance(value, FailureCode) else None


def _failed(result: CommandResult) -> FailureCode | None:
    return parse_codesign_result(result) if not isinstance(result, CommandResult) or result.exit_code != 0 else None


def _lines(result: CommandResult) -> list[str] | None:
    value = result.stderr if result.stderr else result.stdout
    if not isinstance(value, str) or len(value.encode()) > MAX_CAPTURED_OUTPUT_BYTES or _control(value):
        return None
    return [line for line in value.splitlines() if line]


def _control(value: str) -> bool:
    return any(ord(character) < 32 and character not in "\n\r\t" for character in value)


def _safe(value: str) -> bool:
    return bool(value) and not any(ord(character) < 32 for character in value) and len(value.encode()) <= 1024
