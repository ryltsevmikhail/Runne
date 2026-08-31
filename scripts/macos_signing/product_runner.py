import os
import stat
from pathlib import Path

from .command_grammar import parse_command_spec
from .models import CommandResult, CommandSpec, FailureCode
from .product_commands import redact_external_command
from .product_layout import WORK_DIRECTORY
from .runner import (
    LOCAL_TIMEOUT_SECONDS,
    NOTARY_SUBMIT_TIMEOUT_SECONDS,
    LiveRunner,
    executable_program_available,
    run_bounded_subprocess,
)
from .product_provisioning import MAX_PROFILE_OUTPUT_BYTES


class ProductLiveRunner:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._component_runner = LiveRunner(root)

    def run(self, command: CommandSpec) -> CommandResult:
        if parse_command_spec(command) is not None:
            return self._component_runner.run(command)
        try:
            redact_external_command(command)
        except (TypeError, ValueError):
            return _closed(FailureCode.UNKNOWN_STATUS)
        if not executable_program_available(command.program):
            return _closed(FailureCode.TOOL_UNAVAILABLE)
        invocation = self._invocation(command)
        if invocation is None:
            return _closed(FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        argv, expected_output = invocation
        timeout = (
            NOTARY_SUBMIT_TIMEOUT_SECONDS
            if command.phase.startswith("notary-")
            else LOCAL_TIMEOUT_SECONDS
        )
        timeout_failure = (
            FailureCode.NOTARIZATION_FAILED
            if command.phase.startswith("notary-")
            else FailureCode.TOOL_UNAVAILABLE
        )
        result = run_bounded_subprocess(
            [command.program, *argv],
            str(self.root.resolve(strict=True)),
            timeout,
            timeout_failure,
            MAX_PROFILE_OUTPUT_BYTES
            if command.phase == "inspect-provisioning-profile"
            else None,
        )
        if result.exit_code == 0 and expected_output is not None:
            path, kind = expected_output
            if not _existing_kind(path, kind):
                return _closed(FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        return result

    def _invocation(
        self,
        command: CommandSpec,
    ) -> tuple[list[str], tuple[Path, str] | None] | None:
        try:
            root = self.root.resolve(strict=True)
            if not _private_workspace(root):
                return None
            argv = list(command.argv)
            inputs, output = _path_contract(command.phase)
            for index, kind, scope in inputs:
                path = _existing(root, argv[index], kind, scope)
                if path is None:
                    return None
                argv[index] = str(path)
            expected_output = None
            if output is not None:
                index, kind = output
                path = _new_output(root, argv[index])
                if path is None:
                    return None
                argv[index] = str(path)
                expected_output = (path, kind)
            return argv, expected_output
        except (IndexError, OSError, ValueError):
            return None


def _path_contract(phase: str):
    contracts = {
        "inspect-provisioning-profile": (((3, "file", "root"),), None),
        "package-app-zip": (((4, "directory", "root"),), (5, "file")),
        "notary-app-submit": (
            ((2, "file", "root"), (6, "file", "external")),
            None,
        ),
        "staple-app": (((2, "directory", "root"),), None),
        "validate-app": (((2, "directory", "root"),), None),
        "gatekeeper-app": (((3, "directory", "root"),), None),
        "stage-dmg-app": (((0, "directory", "root"),), (1, "directory")),
        "create-dmg": (((4, "directory", "root"),), (7, "file")),
        "sign-dmg": (((4, "file", "root"),), None),
        "verify-dmg": (((2, "file", "root"),), None),
        "notary-dmg-submit": (
            ((2, "file", "root"), (6, "file", "external")),
            None,
        ),
        "staple-dmg": (((2, "file", "root"),), None),
        "validate-dmg": (((2, "file", "root"),), None),
    }
    try:
        return contracts[phase]
    except KeyError:
        raise ValueError("unknown product phase") from None


def _existing(root: Path, token: str, kind: str, scope: str) -> Path | None:
    path = Path(token)
    if scope == "external":
        return _external_file(path) if kind == "file" else None
    if path.is_absolute() or ".." in path.parts:
        return None
    try:
        joined = root / path
        if joined.is_symlink():
            return None
        resolved = joined.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    if resolved.is_symlink():
        return None
    if kind == "file" and not _regular_existing(resolved):
        return None
    if kind == "directory" and not resolved.is_dir():
        return None
    return resolved


def _new_output(root: Path, token: str) -> Path | None:
    path = Path(token)
    if path.is_absolute() or ".." in path.parts:
        return None
    output = root / path
    try:
        parent = output.parent.resolve(strict=True)
        parent.relative_to(root)
    except (OSError, ValueError):
        return None
    if output.exists() or output.is_symlink():
        return None
    return output


def _regular_existing(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def _existing_kind(path: Path, kind: str) -> bool:
    return _regular_existing(path) if kind == "file" else path.is_dir() and not path.is_symlink()


def _external_file(path: Path) -> Path | None:
    try:
        if not path.is_absolute() or path.is_symlink():
            return None
        information = path.lstat()
        if not stat.S_ISREG(information.st_mode) or path.resolve(strict=True) != path:
            return None
        return path
    except (OSError, ValueError):
        return None


def _private_workspace(root: Path) -> bool:
    path = root / WORK_DIRECTORY
    try:
        information = path.lstat()
        return (
            not path.is_symlink()
            and stat.S_ISDIR(information.st_mode)
            and information.st_uid == os.getuid()
            and stat.S_IMODE(information.st_mode) & 0o077 == 0
        )
    except OSError:
        return False


def _closed(code: FailureCode) -> CommandResult:
    return CommandResult(127, "", code.value)
