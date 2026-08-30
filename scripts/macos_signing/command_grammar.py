from dataclasses import dataclass
from pathlib import Path

from .models import CommandSpec, EntitlementBinding

CODESIGN = "/usr/bin/codesign"
SPCTL = "/usr/sbin/spctl"
XCRUN = "/usr/bin/xcrun"


@dataclass(frozen=True)
class ParsedCommand:
    operation: str
    target: str
    hardened_runtime: bool
    entitlement_sha256: str | None
    path_indexes: tuple[int, ...]
    entitlement_index: int | None = None


def parse_command_spec(command: CommandSpec) -> ParsedCommand | None:
    if not isinstance(command, CommandSpec) or command.candidate_relative_cwd != ".":
        return None
    if not _artifact_binding_is_exact(command):
        return None
    try:
        if command.program == CODESIGN:
            return _codesign(command)
        if command.program == XCRUN:
            return _xcrun(command)
        if command.program == SPCTL:
            return _spctl(command)
    except (IndexError, TypeError, ValueError):
        return None
    return None


def _artifact_binding_is_exact(command: CommandSpec) -> bool:
    if command.phase == "notary-submit":
        from .state import NotarizationArtifactBinding

        return isinstance(command.notarization_artifact, NotarizationArtifactBinding)
    return command.notarization_artifact is None


def _codesign(command: CommandSpec) -> ParsedCommand | None:
    argv, phase = command.argv, command.phase
    if phase.startswith("sign-"):
        if len(argv) == 9:
            return _product_codesign(command)
        runtime = len(argv) == 8 and argv[5:7] == ("--options", "runtime")
        if len(argv) not in (6, 8) or argv[:2] != ("--force", "--sign") or argv[3] != "--entitlements":
            return None
        if (len(argv) == 8) != runtime or not _identity(argv[2]) or (runtime and argv[2] == "-"):
            return None
        if not isinstance(command.entitlement, EntitlementBinding) or argv[4] != _suffix(phase) + ".plist":
            return None
        target = _phase_target(phase, argv[-1])
        return ParsedCommand("sign", target, runtime, command.entitlement.sha256, (len(argv) - 1,), 4) if target else None
    if phase.startswith("verify-"):
        if len(argv) != 3 or argv[:2] != ("--verify", "--strict"):
            return None
        target = _phase_target(phase, argv[-1])
        return ParsedCommand("verify", target, False, None, (len(argv) - 1,)) if target else None
    if (
        phase.startswith("metadata-")
        and len(argv) == 2
        and argv[0] in ("-dvv", "-dvvv")
    ):
        target = _phase_target(phase, argv[-1])
        return ParsedCommand("metadata", target, False, None, (1,)) if target else None
    if phase.startswith("requirement-") and len(argv) == 3 and argv[:2] == ("-d", "-r-"):
        target = _phase_target(phase, argv[-1])
        return ParsedCommand("requirement", target, False, None, (2,)) if target else None
    if phase.startswith("entitlements-") and len(argv) == 4 and argv[:3] == ("-d", "--entitlements", ":-"):
        target = _phase_target(phase, argv[-1])
        return ParsedCommand("entitlements", target, False, None, (3,)) if target else None
    return None


def _xcrun(command: CommandSpec) -> ParsedCommand | None:
    argv, phase = command.argv, command.phase
    if phase == "notary-submit" and len(argv) == 8 and argv[:2] == ("notarytool", "submit") and argv[3:] == ("--keychain-profile", argv[4], "--wait", "--output-format", "json"):
        return ParsedCommand("submit", argv[2], False, None, (2,)) if _zip(argv[2]) and _reference(argv[4]) else None
    if phase in ("staple-staple", "staple-validate") and len(argv) == 3 and argv[:1] == ("stapler",) and argv[1] == phase.removeprefix("staple-"):
        return ParsedCommand(argv[1], argv[2], False, None, (2,)) if _app(argv[2]) else None
    return None


def _spctl(command: CommandSpec) -> ParsedCommand | None:
    argv = command.argv
    if command.phase == "gatekeeper" and len(argv) == 4 and argv[:3] == ("--assess", "--type", "execute") and _app(argv[3]):
        return ParsedCommand("assess", argv[3], False, None, (3,))
    return None


def _phase_target(phase: str, target: str) -> str | None:
    suffix = _suffix(phase)
    if suffix == "daemon" and _daemon(target):
        return target
    if suffix == "cli" and _cli(target):
        return target
    if suffix == "app" and _app(target):
        return target
    return None


def _suffix(phase: str) -> str:
    return phase.rsplit("-", 1)[-1]


def _relative(value: object) -> bool:
    path = Path(value) if isinstance(value, str) else Path()
    return isinstance(value, str) and bool(value) and not path.is_absolute() and ".." not in path.parts


def _app(value: str) -> bool:
    return _relative(value) and len(Path(value).parts) == 1 and Path(value).suffix == ".app"


def _zip(value: str) -> bool:
    return _relative(value) and len(Path(value).parts) == 1 and Path(value).suffix == ".zip"


def _daemon(value: str) -> bool:
    path = Path(value)
    return _relative(value) and len(path.parts) == 4 and path.parts[1:] == ("Contents", "MacOS", "runned") and _app(path.parts[0])


def _cli(value: str) -> bool:
    path = Path(value)
    return _relative(value) and len(path.parts) == 4 and path.parts[1:] == ("Contents", "MacOS", "runne") and _app(path.parts[0])


def _product_codesign(command: CommandSpec) -> ParsedCommand | None:
    argv, phase = command.argv, command.phase
    if (
        argv[:2] != ("--force", "--sign")
        or argv[3:7] != ("--timestamp", "--options", "runtime", "--entitlements")
        or not _identity(argv[2])
        or argv[2] == "-"
        or argv[7] != _suffix(phase) + ".plist"
        or not isinstance(command.entitlement, EntitlementBinding)
    ):
        return None
    target = _phase_target(phase, argv[8])
    if target is None:
        return None
    return ParsedCommand("sign", target, True, command.entitlement.sha256, (8,), 7)


def _reference(value: object) -> bool:
    return isinstance(value, str) and bool(value) and not value.startswith("-")


def _identity(value: str) -> bool:
    return value == "-" or _reference(value)
