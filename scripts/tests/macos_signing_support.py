import contextlib
import importlib
import io
import json
import plistlib
import runpy
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.macos_signing.commands import build_sign_command, build_verify_command, bundle_target, rooted_target
from scripts.macos_signing.evidence import normalize_evidence
from scripts.macos_signing.models import (
    CommandResult,
    CommandSpec,
    EvidenceTarget,
    ExecutionMode,
    SignatureExpectation,
    SigningOutcome,
    SigningProfile,
    SigningRequest,
    ValidatedTarget,
)
from scripts.macos_signing.runner import FakeRunner
from scripts.macos_signing.validation import validate_request

_REQUEST_TEMPORARY_DIRECTORIES: list[tempfile.TemporaryDirectory[str]] = []


class RecordingRunner:
    def __init__(self, results: tuple[CommandResult, ...] = ()) -> None:
        self.commands: list[CommandSpec] = []
        self.results = results

    def run(self, command: CommandSpec) -> CommandResult:
        self.commands.append(command)
        return self.results[len(self.commands) - 1]


def make_candidate(name: str = "GOCODE.app") -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
    temporary_directory = tempfile.TemporaryDirectory()
    candidate = Path(temporary_directory.name) / name
    macos = candidate / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    (candidate / "Contents" / "Resources").mkdir()
    main = macos / "GOCODE"
    daemon = macos / "gocoded"
    main.write_bytes(b"synthetic main executable\n")
    daemon.write_bytes(b"synthetic daemon executable\n")
    main.chmod(0o755)
    daemon.chmod(0o755)
    app_entitlements = candidate / "app.plist"
    daemon_entitlements = candidate / "daemon.plist"
    app_entitlements.write_bytes(plistlib.dumps({}))
    daemon_entitlements.write_bytes(plistlib.dumps({}))
    (candidate / "Contents" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleName": "synthetic"}))
    (candidate / "Contents" / "Resources" / "fixture.txt").write_bytes(b"synthetic resource\n")
    return temporary_directory, candidate, app_entitlements, daemon_entitlements


def make_request() -> SigningRequest:
    temporary_directory, candidate, app_entitlements, daemon_entitlements = make_candidate()
    _REQUEST_TEMPORARY_DIRECTORIES.append(temporary_directory)
    request = SigningRequest(
        profile=SigningProfile.DEVELOPMENT_AD_HOC,
        candidate_app=candidate,
        production_bundle_id=None,
        app_entitlements=app_entitlements,
        daemon_entitlements=daemon_entitlements,
        execution_mode=ExecutionMode.FAKE,
        keychain_profile_ref=None,
        release_candidate_sha256="0" * 64,
    )
    return request


def make_production_request() -> SigningRequest:
    return replace(
        make_request(),
        profile=SigningProfile.PRODUCTION_DEVELOPER_ID,
        production_bundle_id="com.example.gocode",
    )


def missing_production_request(keychain_profile_ref: str | None) -> SigningRequest:
    return SigningRequest(
        SigningProfile.PRODUCTION_DEVELOPER_ID,
        Path("missing.app"),
        "com.example.gocode",
        Path("missing-app.plist"),
        Path("missing-daemon.plist"),
        ExecutionMode.FAKE,
        keychain_profile_ref,
        "0" * 64,
    )


def cleanup_request_fixtures() -> None:
    while _REQUEST_TEMPORARY_DIRECTORIES:
        _REQUEST_TEMPORARY_DIRECTORIES.pop().cleanup()


def make_fake_runner() -> FakeRunner:
    return FakeRunner((), ())


def run_production_wrapper() -> tuple[int, dict[str, object], str, bool, bool]:
    output, error = io.StringIO(), io.StringIO()
    script_root = str(Path(__file__).parents[1])
    with mock.patch.object(sys, "path", [script_root, *sys.path]):
        runner_module = importlib.import_module("macos_signing.runner")
    runner = mock.patch.object(runner_module.FakeRunner, "run")
    process = mock.patch.object(runner_module.subprocess, "run")
    with (
        mock.patch.object(sys, "argv", ["prepare-macos-signing.py", "--profile", "production-developer-id", "--candidate-app", "synthetic-candidate.app", "--production-bundle-id", "com.example.gocode", "--execution-mode", "fake"]),
        mock.patch.object(sys, "platform", "darwin"), runner as fake_run, process as subprocess_run,
        mock.patch.object(sys, "path", [script_root, *sys.path]),
        contextlib.redirect_stdout(output), contextlib.redirect_stderr(error),
    ):
        try:
            runpy.run_path(Path(__file__).parents[1] / "prepare-macos-signing.py", run_name="__main__")
        except SystemExit as exit_error:
            exit_code = exit_error.code
    return exit_code, json.loads(output.getvalue()), error.getvalue(), fake_run.called, subprocess_run.called


def make_validated_targets() -> tuple[ValidatedTarget, ValidatedTarget]:
    return (
        ValidatedTarget("GOCODE.app/Contents/MacOS/gocoded", "d" * 64),
        ValidatedTarget("GOCODE.app", "a" * 64),
    )


def make_bundle_target() -> ValidatedTarget:
    return ValidatedTarget("GOCODE.app", "a" * 64)


def mutate_candidate(request: SigningRequest, action: str) -> SigningRequest:
    candidate = request.candidate_app
    contents = candidate / "Contents"
    macos = contents / "MacOS"
    main = macos / "GOCODE"
    daemon = macos / "gocoded"
    if action == "missing_daemon":
        daemon.unlink()
    elif action == "unsigned_daemon":
        daemon.chmod(0o644)
    elif action == "candidate_symlink":
        linked = candidate.parent / "Linked.app"
        linked.symlink_to(candidate, target_is_directory=True)
        return replace(request, candidate_app=linked)
    elif action in ("contents_symlink", "macos_symlink"):
        path = contents if action == "contents_symlink" else macos
        target = candidate / ("contents-target" if path == contents else "macos-target")
        path.rename(target)
        path.symlink_to(target, target_is_directory=True)
    elif action in ("main_symlink", "daemon_symlink"):
        path = main if action == "main_symlink" else daemon
        target = candidate / ("main-target" if path == main else "daemon-target")
        path.rename(target)
        path.symlink_to(target)
    elif action == "extra_executable":
        extra = macos / "unexpected"
        extra.write_bytes(b"synthetic extra executable\n")
        extra.chmod(0o755)
    elif action == "missing_main":
        main.unlink()
    elif action == "non_executable_main":
        main.chmod(0o644)
    return request


def development_evidence():
    return development_workflow()[1].evidence


def development_evidence_from_golden():
    evidence = development_evidence()
    if normalize_evidence(evidence) != golden_evidence_bytes():
        raise ValueError("development golden is not canonical")
    return evidence.candidate.identity, evidence.candidate.signature, evidence


def production_evidence(main_bytes: bytes = b"synthetic main executable\n"):
    from scripts.tests.macos_signing_production_support import production_evidence as build

    state, expectation, evidence, _, _, _ = build(main_bytes)
    return state.candidate.candidate, expectation, evidence


def replace_evidence_signature(evidence, field: str, value: str):
    return replace(evidence, candidate=replace(evidence.candidate, signature=replace(evidence.candidate.signature, **{field: value})))


def replace_evidence_identity(evidence, field: str, value: str):
    if field == "cdhash":
        return replace_evidence_signature(evidence, field, value)
    return replace(evidence, candidate=replace(evidence.candidate, identity=replace(evidence.candidate.identity, **{field: value})))


def replace_evidence_disposition(evidence, **changes: str):
    return replace(evidence, **changes)


def expected_target() -> EvidenceTarget:
    return EvidenceTarget("synthetic-GOCODE.app", "Contents/MacOS/GOCODE", "Contents/MacOS/gocoded")


def replace_target(target: EvidenceTarget, **changes: str) -> EvidenceTarget:
    return replace(target, **changes)


def replace_execution(evidence, index: int, **changes: str):
    records = list(evidence.commands)
    records[index] = replace(records[index], **changes)
    return replace(evidence, commands=tuple(records))


def remove_execution(evidence, phase: str):
    return replace(evidence, commands=tuple(record for record in evidence.commands if record.phase != phase))


def reorder_executions(evidence):
    records = list(evidence.commands)
    records[0], records[1] = records[1], records[0]
    return replace(evidence, commands=tuple(records))


def development_request_and_runner(results: tuple[CommandResult, ...] = (CommandResult(0, "", ""),) * 4) -> tuple[SigningRequest, FakeRunner]:
    request = make_request()
    candidate = validate_request(request)
    daemon, app = rooted_target(candidate, candidate.daemon), bundle_target(candidate)
    commands = (
        build_sign_command(daemon, Path("daemon.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", candidate.daemon_entitlements),
        build_verify_command(daemon, SigningProfile.DEVELOPMENT_AD_HOC),
        build_sign_command(app, Path("app.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", candidate.app_entitlements),
        build_verify_command(app, SigningProfile.DEVELOPMENT_AD_HOC),
    )
    return request, FakeRunner(commands, results)


def development_workflow(results: tuple[CommandResult, ...] = (CommandResult(0, "", ""),) * 4) -> tuple[FakeRunner, SigningOutcome]:
    from scripts.macos_signing import prepare_signing

    request, runner = development_request_and_runner(results)
    return runner, prepare_signing(request, runner, "darwin")


def development_fake_outcome() -> SigningOutcome:
    return development_workflow()[1]


def golden_evidence_bytes() -> bytes:
    return Path(__file__).parents[1].joinpath("macos_signing", "fixtures", "development-ad-hoc-evidence.v1.json").read_bytes()
