import plistlib
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.macos_signing.commands import build_gatekeeper_command, build_notary_submit_command, build_staple_command, build_verify_command, bundle_target
from scripts.macos_signing.evidence import normalize_evidence
from scripts.macos_signing.execution import execution_records
from scripts.macos_signing.models import CommandResult, CommandSpec, FailureCode, SigningProfile
from scripts.macos_signing.observations import (
    parse_designated_requirement, parse_embedded_entitlements, parse_signature_metadata,
)
from scripts.macos_signing.runner import LiveRunner
from scripts.macos_signing.state import CandidateStage, CandidateState, bind_notarization_artifact
from scripts.macos_signing import prepare_signing
from scripts.tests import macos_signing_support


def assert_state_snapshots(case) -> None:
    runner, outcome = macos_signing_support.development_workflow()
    case.assertEqual((outcome.evidence.snapshot_stage, len(runner.commands)), ("APP_SIGNED", 4))
    case.assertEqual([item.phase for item in runner.commands], ["sign-daemon", "verify-daemon", "sign-app", "verify-app"])


def assert_notary_submit_contract(case) -> None:
    temporary, candidate, app_entitlements, daemon_entitlements = macos_signing_support.make_candidate()
    case.addCleanup(temporary.cleanup)
    archive = candidate.parent / "candidate.zip"
    archive.write_bytes(b"synthetic zip\n")
    request = replace(macos_signing_support.make_request(), candidate_app=candidate, app_entitlements=app_entitlements, daemon_entitlements=daemon_entitlements)
    validated = macos_signing_support.validate_request(request)
    state = CandidateState(validated, CandidateStage.APP_SIGNED)
    binding = bind_notarization_artifact(candidate.parent, archive.name, state)
    command = build_notary_submit_command(binding, "opaque-ref")
    case.assertEqual(command.argv, ("notarytool", "submit", "candidate.zip", "--keychain-profile", "opaque-ref", "--wait", "--output-format", "json"))
    case.assertEqual(command.phase, "notary-submit")


def assert_notary_binding_grammar(case) -> None:
    temporary, candidate, app_entitlements, daemon_entitlements = macos_signing_support.make_candidate()
    case.addCleanup(temporary.cleanup)
    archive = candidate.parent / "candidate.zip"
    archive.write_bytes(b"synthetic zip\n")
    request = replace(macos_signing_support.make_request(), candidate_app=candidate, app_entitlements=app_entitlements, daemon_entitlements=daemon_entitlements)
    validated = macos_signing_support.validate_request(request)
    binding = bind_notarization_artifact(candidate.parent, archive.name, CandidateState(validated, CandidateStage.APP_SIGNED))
    unbound = CommandSpec("notary-submit", "/usr/bin/xcrun", ("notarytool", "submit", "candidate.zip", "--keychain-profile", "opaque-ref", "--wait", "--output-format", "json"), ".")
    valid_verify = macos_signing_support.build_verify_command(macos_signing_support.bundle_target(validated), SigningProfile.DEVELOPMENT_AD_HOC)
    rebound = replace(valid_verify, notarization_artifact=binding)
    for command in (unbound, rebound):
        with case.subTest(phase=command.phase):
            with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
                case.assertEqual(LiveRunner(candidate.parent).run(command).stderr, FailureCode.UNKNOWN_STATUS.value)
            run.assert_not_called()
            with case.assertRaises(ValueError):
                execution_records((command,), (CommandResult(0, '{"status":"Accepted"}', ""),), macos_signing_support.expected_target())


def assert_checked_observation_contract(case) -> None:
    metadata = CommandResult(0, "", "Identifier=com.example.gocode\nTeamIdentifier=TEAM000001\nAuthority=Developer ID Application: Synthetic (TEAM000001)\nCDHash=" + "c" * 40 + "\nCodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1+5\n")
    observed = parse_signature_metadata(metadata)
    requirement = parse_designated_requirement(CommandResult(0, "designated => identifier com.example.gocode\n", ""))
    case.assertNotIsInstance(observed, FailureCode)
    case.assertNotIsInstance(requirement, FailureCode)
    for result, code in ((CommandResult(0, "", metadata.stderr + "Identifier=duplicate\n"), FailureCode.UNKNOWN_STATUS), (CommandResult(0, "", metadata.stderr.replace("runtime", "other")), FailureCode.HARDENED_RUNTIME_MISSING), (CommandResult(0, "designated => bad\x01\n", ""), FailureCode.UNKNOWN_STATUS), (CommandResult(0, plistlib.dumps({"unexpected": True}).decode(), ""), FailureCode.ENTITLEMENTS_MISMATCH), (CommandResult(0, "not-a-plist", ""), FailureCode.UNKNOWN_STATUS)):
        with case.subTest(result=result):
            if "CodeDirectory" in result.stderr or "Identifier" in result.stderr:
                case.assertEqual(parse_signature_metadata(result), code)
            elif result.stdout.startswith("designated"):
                case.assertEqual(parse_designated_requirement(result), code)
            else:
                case.assertEqual(parse_embedded_entitlements(result), code)


def assert_real_code_directory_contract(case) -> None:
    prefix = "Identifier=com.example.gocode\nTeamIdentifier=TEAM000001\nAuthority=Developer ID Application: Synthetic (TEAM000001)\nCDHash=" + "c" * 40 + "\n"
    accepted = CommandResult(0, "", prefix + "CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1+5 location=embedded\n")
    case.assertNotIsInstance(parse_signature_metadata(accepted), FailureCode)
    for line, code in (("CodeDirectory v=20500 flags=0x0(runtime)\n", FailureCode.HARDENED_RUNTIME_MISSING), ("CodeDirectory v=20500 flags=0x10000(other)\n", FailureCode.HARDENED_RUNTIME_MISSING), ("CodeDirectory=v=20500 flags=0x10000(runtime)\n", FailureCode.UNKNOWN_STATUS), ("CodeDirectory v=abc flags=0x10000(runtime)\n", FailureCode.UNKNOWN_STATUS), ("CodeDirectory v=20500 flags=0x10000(runtime)\nCodeDirectory v=20500 flags=0x10000(runtime)\n", FailureCode.UNKNOWN_STATUS)):
        with case.subTest(line=line):
            case.assertEqual(parse_signature_metadata(CommandResult(0, "", prefix + line)), code)


def assert_production_evidence_provenance(case) -> None:
    import scripts.macos_signing.evidence as evidence
    import scripts.macos_signing.observations as observations
    from scripts.tests.macos_signing_production_support import production_evidence

    case.assertFalse(hasattr(evidence, "build_evidence"))
    case.assertFalse(hasattr(observations, "CheckedObservationBundle"))
    case.assertTrue(callable(getattr(evidence, "build_production_evidence_from_results", None)))
    state, expectation, valid, commands, results, target = production_evidence()
    candidate = state.candidate.candidate
    case.assertEqual(evidence.validate_production_evidence(valid, candidate, expectation, "darwin", target).code, FailureCode.BLOCKED_CREDENTIALS)
    duplicate = next(item for item in commands if item.phase == "metadata-daemon")
    case.assertEqual(evidence.build_production_evidence_from_results(state, expectation, expectation, "darwin", target, commands + (duplicate,), results + (CommandResult(0, "", "malformed"),)).code, FailureCode.EVIDENCE_INCOMPLETE)
    for phase, result in (("metadata-daemon", CommandResult(0, "", "malformed")), ("requirement-daemon", CommandResult(0, "not-designated", "")), ("entitlements-daemon", CommandResult(0, "not-a-plist", ""))):
        with case.subTest(phase=phase):
            _, _, failed, malformed_commands, malformed_results, malformed_target = production_evidence(replacement=(phase, result))
            case.assertEqual(failed.code, FailureCode.UNKNOWN_STATUS)
            record = execution_records(malformed_commands, malformed_results, malformed_target)[next(index for index, item in enumerate(malformed_commands) if item.phase == phase)]
            case.assertEqual(record.outcome, failed.code.value)


def assert_live_notary_artifact_binding(case) -> None:
    temporary, candidate, app_entitlements, daemon_entitlements = macos_signing_support.make_candidate()
    case.addCleanup(temporary.cleanup)
    archive = candidate.parent / "candidate.zip"
    archive.write_bytes(b"synthetic zip\n")
    request = replace(macos_signing_support.make_request(), candidate_app=candidate, app_entitlements=app_entitlements, daemon_entitlements=daemon_entitlements)
    validated = macos_signing_support.validate_request(request)
    binding = bind_notarization_artifact(candidate.parent, archive.name, CandidateState(validated, CandidateStage.APP_SIGNED))
    command = build_notary_submit_command(binding, "opaque-ref")
    with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run", return_value=mock.Mock(returncode=0)) as run:
        LiveRunner(candidate.parent).run(command)
    case.assertEqual(run.call_args.args[0][3], str(archive.resolve()))
    (candidate / "Contents" / "MacOS" / "GOCODE").write_bytes(b"replaced source\n")
    with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
        case.assertEqual(LiveRunner(candidate.parent).run(command).stderr, FailureCode.ARTIFACT_IDENTITY_MISMATCH.value)
    run.assert_not_called()
    (candidate / "Contents" / "MacOS" / "GOCODE").write_bytes(b"synthetic main executable\n")
    archive.write_bytes(b"replaced synthetic zip\n")
    with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
        case.assertEqual(LiveRunner(candidate.parent).run(command).stderr, FailureCode.ARTIFACT_IDENTITY_MISMATCH.value)
    run.assert_not_called()


def assert_phase_specific_timeouts(case) -> None:
    temporary, candidate, app_entitlements, daemon_entitlements = macos_signing_support.make_candidate()
    case.addCleanup(temporary.cleanup)
    archive = candidate.parent / "candidate.zip"
    archive.write_bytes(b"synthetic zip\n")
    request = replace(macos_signing_support.make_request(), candidate_app=candidate, app_entitlements=app_entitlements, daemon_entitlements=daemon_entitlements)
    validated = macos_signing_support.validate_request(request)
    binding = bind_notarization_artifact(candidate.parent, archive.name, CandidateState(validated, CandidateStage.APP_SIGNED))
    notary = build_notary_submit_command(binding, "opaque-ref")
    local = (build_verify_command(bundle_target(validated), SigningProfile.DEVELOPMENT_AD_HOC), build_staple_command(bundle_target(validated), "staple"), build_gatekeeper_command(bundle_target(validated)))
    with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run", return_value=mock.Mock(returncode=0)) as run:
        LiveRunner(candidate.parent).run(notary)
        case.assertEqual(run.call_args.kwargs["timeout"], 1800)
        for command in local:
            LiveRunner(candidate.parent).run(command)
            case.assertEqual(run.call_args.kwargs["timeout"], 60)
    with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("xcrun", 1800)) as run:
        case.assertEqual(LiveRunner(candidate.parent).run(notary).stderr, FailureCode.NOTARIZATION_FAILED.value)
    run.assert_called_once()


def assert_actual_development_golden(case) -> None:
    first_request, first_runner = macos_signing_support.development_request_and_runner()
    second_request, second_runner = macos_signing_support.development_request_and_runner()
    first, second = prepare_signing(first_request, first_runner, "darwin"), prepare_signing(second_request, second_runner, "darwin")
    first_bytes, second_bytes = normalize_evidence(first.evidence), normalize_evidence(second.evidence)
    case.assertEqual(first_bytes, second_bytes)
    case.assertEqual(first_bytes, macos_signing_support.golden_evidence_bytes())
    case.assertEqual(len(first.evidence.commands), 4)
    for token in (b"Developer ID", b"TEAM", b"cdhash", b"notary"):
        case.assertNotIn(token, first_bytes)
