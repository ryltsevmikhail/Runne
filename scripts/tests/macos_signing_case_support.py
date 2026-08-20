import hashlib
import os
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.macos_signing.commands import build_sign_command, build_verify_command, bundle_target
from scripts.macos_signing.evidence import normalize_evidence, validate_production_evidence
from scripts.macos_signing.execution import execution_records
from scripts.macos_signing.models import CommandResult, CommandSpec, EntitlementBinding, EvidenceTarget, ExecutionMode, FailureCode, SigningProfile
from scripts.macos_signing.parsers import parse_codesign_result
from scripts.macos_signing.runner import LiveRunner
from scripts.macos_signing.validation import revalidate_candidate, validate_request
from scripts.tests import macos_signing_support


def assert_replay_and_tree_rejection(case) -> None:
    _, signature, evidence = macos_signing_support.production_evidence()
    replacement, _, _ = macos_signing_support.production_evidence(b"different synthetic candidate\n")
    failure = validate_production_evidence(evidence, replacement, signature, "darwin", macos_signing_support.expected_target())
    case.assertEqual(failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
    invalid = macos_signing_support.replace_execution(evidence, 0, target="wrong-target")
    failure = validate_production_evidence(invalid, evidence.candidate.identity, signature, "darwin", macos_signing_support.expected_target())
    case.assertEqual(failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
    invalid = macos_signing_support.reorder_executions(evidence)
    failure = validate_production_evidence(invalid, evidence.candidate.identity, signature, "darwin", macos_signing_support.expected_target())
    case.assertEqual(failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
    case.addCleanup(macos_signing_support.cleanup_request_fixtures)
    request = macos_signing_support.make_request()
    resource = request.candidate_app / "Contents" / "Resources" / "safe-link"
    resource.symlink_to("fixture.txt")
    captured = validate_request(request)
    resource.unlink()
    resource.symlink_to("../Info.plist")
    case.assertEqual(revalidate_candidate(request.candidate_app, captured).code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
    macos_signing_support.cleanup_request_fixtures()
    request = macos_signing_support.make_request()
    outside = request.candidate_app.parent / "outside-target"
    outside.write_bytes(b"outside candidate\n")
    (request.candidate_app / "Contents" / "Resources" / "unsafe-link").symlink_to(outside)
    case.assertEqual(validate_request(request).code, FailureCode.ARTIFACT_NOT_FOUND)
    macos_signing_support.cleanup_request_fixtures()
    for relative in (Path("../../../outside-target"),):
        with case.subTest(link=relative):
            request = macos_signing_support.make_request()
            outside = request.candidate_app.parent / "outside-target"
            outside.write_bytes(b"outside candidate\n")
            (request.candidate_app / "Contents" / "Resources" / "unsafe-link").symlink_to(relative)
            case.assertEqual(validate_request(request).code, FailureCode.ARTIFACT_NOT_FOUND)
    if hasattr(os, "mkfifo"):
        request = macos_signing_support.make_request()
        os.mkfifo(request.candidate_app / "Contents" / "Resources" / "special")
        case.assertEqual(validate_request(request).code, FailureCode.ARTIFACT_NOT_FOUND)


def assert_live_runner_contract(case) -> None:
    temporary_directory, candidate, app_entitlements, daemon_entitlements = macos_signing_support.make_candidate()
    case.addCleanup(temporary_directory.cleanup)
    _, app = macos_signing_support.make_validated_targets()
    command = build_verify_command(app, SigningProfile.DEVELOPMENT_AD_HOC)
    invalid = (
        CommandSpec("verify-app", "/usr/bin/codesign", ("--keychain", "ignored", app.relative_path), "."),
        CommandSpec("unknown", "/usr/bin/codesign", command.argv, "."),
        CommandSpec("sign-daemon", "/usr/bin/codesign", ("--verify", "--strict", "Runne.app/Contents/MacOS/runned"), "."),
        CommandSpec("verify-app", "/usr/bin/codesign", ("--verify", app.relative_path), "."),
        CommandSpec("sign-app", "/usr/bin/codesign", ("--force", "--sign", "-", "--entitlements", "app.plist", "--options", "runtime", app.relative_path), "."),
        CommandSpec("notary-submit", "/usr/bin/xcrun", ("arbitrary", "subtool"), "."),
        CommandSpec("notary-submit", "/usr/bin/xcrun", ("notarytool", "submit", app.relative_path, "--unknown", "opaque"), "."),
        CommandSpec("staple-staple", "/usr/bin/xcrun", ("stapler", "staple", app.relative_path, "--extra"), "."),
        CommandSpec("gatekeeper", "/usr/sbin/spctl", ("--assess", "--type", "execute", app.relative_path, "--extra"), "."),
    )
    with (
        mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True),
        mock.patch("scripts.macos_signing.runner.os.access", return_value=True),
        mock.patch("scripts.macos_signing.runner.subprocess.run", return_value=mock.Mock(returncode=0)) as run,
    ):
        result = LiveRunner(candidate.parent).run(command)
        for malformed in invalid:
            with case.subTest(argv=malformed.argv):
                case.assertEqual(parse_codesign_result(LiveRunner(candidate.parent).run(malformed)), FailureCode.UNKNOWN_STATUS)
    run.assert_called_once()
    argv, = run.call_args.args
    # The runner canonicalizes every candidate path via resolve(strict=True);
    # on macOS the temporary directory lives under /private/var, so the
    # expected argv must be the resolved path, not the literal one.
    case.assertEqual(argv, ["/usr/bin/codesign", "--verify", "--strict", str((candidate.parent / app.relative_path).resolve(strict=True))])
    case.assertFalse(run.call_args.kwargs["shell"])
    case.assertEqual(set(run.call_args.kwargs["env"]), {"PATH", "LANG", "LC_ALL"})
    case.assertEqual(run.call_args.kwargs["timeout"], 60)
    case.assertNotIn("text", run.call_args.kwargs)
    case.assertFalse(run.call_args.kwargs.get("capture_output", False))
    case.assertLessEqual(len(result.stdout.encode()), 4096)
    def oversized(argv, **kwargs):
        kwargs["stdout"].write(b"x" * 4097)
        return mock.Mock(returncode=0)
    with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run", side_effect=oversized):
        result = LiveRunner(candidate.parent).run(command)
    case.assertEqual(parse_codesign_result(result), FailureCode.UNKNOWN_STATUS)
    request = replace(macos_signing_support.make_request(), candidate_app=candidate, app_entitlements=app_entitlements, daemon_entitlements=daemon_entitlements)
    validated = validate_request(request)
    valid = build_sign_command(bundle_target(validated), Path("app.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", validated.app_entitlements)
    malformed = CommandSpec(valid.phase, valid.program, valid.argv[:-1] + ("--options", "runtime", valid.argv[-1]), ".", valid.entitlement)
    target = EvidenceTarget(candidate.name, "Contents/MacOS/Runne", "Contents/MacOS/runned")
    with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run", return_value=mock.Mock(returncode=0)) as run:
        case.assertEqual(parse_codesign_result(LiveRunner(candidate.parent).run(malformed)), FailureCode.UNKNOWN_STATUS)
        with case.assertRaises(ValueError):
            execution_records((malformed,), (CommandResult(0, "", ""),), target)
        case.assertIsNone(parse_codesign_result(LiveRunner(candidate.parent).run(valid)))
    case.assertEqual(len(execution_records((valid,), (CommandResult(0, "", ""),), target)), 1)
    run.assert_called_once()


def assert_entitlement_binding_contract(case) -> None:
    temporary_directory, candidate, app_entitlements, _ = macos_signing_support.make_candidate()
    case.addCleanup(temporary_directory.cleanup)
    binding = validate_request(macos_signing_support.make_request()).app_entitlements
    with case.assertRaises(ValueError):
        EntitlementBinding(Path("relative.plist"), binding.sha256, binding.device, binding.inode)
    parent = app_entitlements.parent / "canonical-parent"
    parent.mkdir()
    noncanonical = parent / ".." / app_entitlements.name
    with case.assertRaises(ValueError):
        EntitlementBinding(noncanonical, binding.sha256, binding.device, binding.inode)
    info = app_entitlements.lstat()
    forged = object.__new__(EntitlementBinding)
    for field, value in (("canonical_path", noncanonical), ("sha256", hashlib.sha256(app_entitlements.read_bytes()).hexdigest()), ("device", info.st_dev), ("inode", info.st_ino)):
        object.__setattr__(forged, field, value)
    command = build_sign_command(bundle_target(validate_request(macos_signing_support.make_request())), Path("app.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", forged)
    with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
        result = LiveRunner(candidate.parent).run(command)
    case.assertEqual(parse_codesign_result(result), FailureCode.ARTIFACT_IDENTITY_MISMATCH)
    run.assert_not_called()


def assert_evidence_cross_binding(case) -> None:
    candidate, signature, evidence = macos_signing_support.production_evidence()
    target = EvidenceTarget("B.app", "Contents/MacOS/Runne", "Contents/MacOS/runned")
    forged = replace(evidence, target=target)
    with case.assertRaises(ValueError):
        normalize_evidence(forged)
    failure = validate_production_evidence(forged, candidate, signature, "darwin", target)
    case.assertEqual(failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)


def assert_development_runner_boundary(case) -> None:
    from scripts.macos_signing import prepare_signing

    request = macos_signing_support.make_request()
    with mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
        outcome = prepare_signing(request, LiveRunner(request.candidate_app.parent), "darwin")
    case.assertEqual(outcome.failure.code, FailureCode.PROFILE_DOWNGRADE_REJECTED)
    case.assertIsNone(outcome.evidence)
    run.assert_not_called()
