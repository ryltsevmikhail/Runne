from typing import Sequence

from .command_grammar import parse_command_spec
from .models import CandidateIdentity, CommandResult, CommandSpec, EvidenceTarget, ExecutionRecord, FailureCode
from .observations import metadata_result_failure, parse_embedded_entitlements, requirement_result_failure
from .parsers import parse_codesign_result, parse_notary_result, parse_spctl_result, parse_stapler_result

_DAEMON_PHASES = {"sign-daemon", "verify-daemon", "metadata-daemon", "requirement-daemon", "entitlements-daemon"}
_MAIN_PHASES = {"sign-app", "verify-app", "metadata-app", "requirement-app", "entitlements-app"}
_CANDIDATE_PHASES = {"notary-submit", "staple-staple", "staple-validate", "gatekeeper"}


def execution_records(commands: Sequence[CommandSpec], results: Sequence[CommandResult], target: EvidenceTarget) -> tuple[ExecutionRecord, ...]:
    if not isinstance(target, EvidenceTarget) or len(commands) != len(results):
        raise ValueError("invalid execution inputs")
    return tuple(_record(command, result, target) for command, result in zip(commands, results))


def expected_records(target: EvidenceTarget, candidate: CandidateIdentity) -> tuple[ExecutionRecord, ...]:
    phases = ("sign-daemon", "verify-daemon", "metadata-daemon", "requirement-daemon", "entitlements-daemon", "sign-app", "verify-app", "metadata-app", "requirement-app", "entitlements-app", "notary-submit", "staple-staple", "staple-validate", "gatekeeper")
    return tuple(_expected(phase, target, candidate) for phase in phases)


def dispositions(records: Sequence[ExecutionRecord]) -> tuple[str, str, str]:
    values = {record.phase: record.outcome for record in records}
    return (_disposition(values, ("notary-submit",)), _disposition(values, ("staple-staple", "staple-validate")), _disposition(values, ("gatekeeper",)))


def _record(command: CommandSpec, result: CommandResult, target: EvidenceTarget) -> ExecutionRecord:
    parsed = parse_command_spec(command)
    if parsed is None:
        raise ValueError("invalid command grammar")
    command_target = target.candidate if parsed.operation == "submit" else parsed.target
    if command_target != _expected_target(command.phase, target):
        raise ValueError("command target mismatch")
    parser = _parser(command.phase)
    failure = parser(result) if parser else FailureCode.UNKNOWN_STATUS
    return ExecutionRecord(command.phase, parsed.operation, command_target, parsed.hardened_runtime, parsed.entitlement_sha256, "success" if failure is None else failure.value)


def _expected(phase: str, target: EvidenceTarget, candidate: CandidateIdentity) -> ExecutionRecord:
    operation = {"sign-daemon": "sign", "verify-daemon": "verify", "metadata-daemon": "metadata", "requirement-daemon": "requirement", "entitlements-daemon": "entitlements", "sign-app": "sign", "verify-app": "verify", "metadata-app": "metadata", "requirement-app": "requirement", "entitlements-app": "entitlements", "notary-submit": "submit", "staple-staple": "staple", "staple-validate": "validate", "gatekeeper": "assess"}[phase]
    digest = candidate.daemon_entitlements_sha256 if phase == "sign-daemon" else candidate.app_entitlements_sha256 if phase == "sign-app" else None
    runtime = phase in {"sign-daemon", "sign-app"}
    return ExecutionRecord(phase, operation, _expected_target(phase, target), runtime, digest, "success")


def _parser(phase: str):
    if phase.startswith(("sign-", "verify-")):
        return parse_codesign_result
    if phase.startswith("metadata-"):
        return metadata_result_failure
    if phase.startswith("requirement-"):
        return requirement_result_failure
    if phase.startswith("entitlements-"):
        return parse_embedded_entitlements
    if phase.startswith("notary-"):
        return parse_notary_result
    if phase.startswith("staple-"):
        return parse_stapler_result
    return parse_spctl_result if phase == "gatekeeper" else None


def _expected_target(phase: str, target: EvidenceTarget) -> str:
    if phase in _DAEMON_PHASES:
        return f"{target.candidate}/{target.daemon}"
    if phase in _MAIN_PHASES:
        return target.candidate
    return target.candidate if phase in _CANDIDATE_PHASES else ""


def _disposition(values: dict[str, str], phases: tuple[str, ...]) -> str:
    return "accepted" if all(values.get(phase) == "success" for phase in phases) else "not-run"
