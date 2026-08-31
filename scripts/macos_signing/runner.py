import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol

from .command_grammar import ParsedCommand, parse_command_spec
from .hashing import sha256_file
from .models import CommandResult, CommandSpec, EntitlementBinding, FailureCode
from .policy import MAX_CAPTURED_OUTPUT_BYTES
from .state import artifact_is_current
from .state import NotarizationArtifactBinding

_ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
LOCAL_TIMEOUT_SECONDS = 60
NOTARY_SUBMIT_TIMEOUT_SECONDS = 1800


class Runner(Protocol):
    def run(self, command: CommandSpec) -> CommandResult: ...


class FakeRunner:
    def __init__(self, expected: tuple[CommandSpec, ...], results: tuple[CommandResult, ...]) -> None:
        self.expected, self.results, self.commands, self._index = expected, results, [], 0

    def run(self, command: CommandSpec) -> CommandResult:
        self.commands.append(command)
        index = self._index
        self._index += 1
        if index >= len(self.expected) or command != self.expected[index] or index >= len(self.results):
            return _closed_result(FailureCode.UNKNOWN_STATUS)
        return self.results[index]


class LiveRunner:
    def __init__(self, candidate_root: Path) -> None:
        self.candidate_root = candidate_root

    def run(self, command: CommandSpec) -> CommandResult:
        if not executable_program_available(command.program):
            return _closed_result(FailureCode.TOOL_UNAVAILABLE)
        if not _artifact_binding_is_exact(command):
            return _closed_result(FailureCode.UNKNOWN_STATUS)
        parsed = parse_command_spec(command)
        if parsed is None:
            return _closed_result(FailureCode.UNKNOWN_STATUS)
        invocation = _contained_invocation(command, parsed, self.candidate_root)
        if invocation is None:
            return _closed_result(FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        argv, cwd = invocation
        timeout_failure = (
            FailureCode.NOTARIZATION_FAILED
            if parsed.operation == "submit"
            else FailureCode.TOOL_UNAVAILABLE
        )
        return run_bounded_subprocess(argv, cwd, _timeout(parsed), timeout_failure)


def executable_program_available(program: str) -> bool:
    path = Path(program)
    return path.is_absolute() and path.is_file() and os.access(path, os.X_OK)


def run_bounded_subprocess(
    argv: list[str],
    cwd: str,
    timeout: int,
    timeout_failure: FailureCode,
    max_output_bytes: int | None = None,
) -> CommandResult:
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(
                argv,
                shell=False,
                cwd=cwd,
                env=_ENVIRONMENT,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
            )
            return _spooled_result(
                completed.returncode,
                stdout,
                stderr,
                max_output_bytes or MAX_CAPTURED_OUTPUT_BYTES,
            )
    except subprocess.TimeoutExpired:
        return _closed_result(timeout_failure)
    except OSError:
        return _closed_result(FailureCode.TOOL_UNAVAILABLE)


def _artifact_binding_is_exact(command: CommandSpec) -> bool:
    return ((command.phase == "notary-submit" and isinstance(command.notarization_artifact, NotarizationArtifactBinding))
            or (command.phase != "notary-submit" and command.notarization_artifact is None))


def _timeout(parsed: ParsedCommand) -> int:
    return NOTARY_SUBMIT_TIMEOUT_SECONDS if parsed.operation == "submit" else LOCAL_TIMEOUT_SECONDS


def _contained_invocation(command: CommandSpec, parsed: ParsedCommand, root: Path) -> tuple[list[str], str] | None:
    try:
        root_path = root.resolve(strict=True)
        if not root_path.is_dir():
            return None
        cwd = _contained_path(root_path, command.candidate_relative_cwd)
        if cwd is None or not cwd.is_dir():
            return None
        argv = list(command.argv)
        for index in parsed.path_indexes:
            path = _contained_path(root_path, argv[index])
            if path is None:
                return None
            argv[index] = str(path)
        if parsed.entitlement_index is not None:
            entitlement = _bound_entitlement(command.entitlement)
            if entitlement is None:
                return None
            argv[parsed.entitlement_index] = str(entitlement)
        if command.notarization_artifact is not None:
            binding = command.notarization_artifact
            if not artifact_is_current(binding, root_path, binding.source_identity):
                return None
            argv[parsed.path_indexes[0]] = str(binding.canonical_path)
        return [command.program, *argv], str(cwd)
    except (IndexError, OSError, ValueError):
        return None


def _contained_path(root: Path, token: str) -> Path | None:
    path = Path(token)
    if path.is_absolute():
        return None
    try:
        resolved = (root / path).resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved


def _bound_entitlement(binding: EntitlementBinding | None) -> Path | None:
    if not isinstance(binding, EntitlementBinding):
        return None
    try:
        path = binding.canonical_path
        if not isinstance(path, Path) or not path.is_absolute():
            return None
        resolved = path.resolve(strict=True)
        if resolved != path:
            return None
        info = resolved.lstat()
        if resolved.is_symlink() or not stat.S_ISREG(info.st_mode):
            return None
        if (info.st_dev, info.st_ino) != (binding.device, binding.inode):
            return None
        if sha256_file(resolved) != binding.sha256:
            return None
    except (OSError, ValueError):
        return None
    return resolved


def _spooled_result(exit_code: int, stdout, stderr, limit: int) -> CommandResult:
    values = []
    for stream in (stdout, stderr):
        stream.seek(0)
        value = stream.read(limit + 1)
        if len(value) > limit:
            return _closed_result(FailureCode.UNKNOWN_STATUS)
        values.append(value.decode("utf-8", "ignore"))
    return CommandResult(exit_code, *values)


def _closed_result(code: FailureCode) -> CommandResult:
    return CommandResult(127, "", code.value)
