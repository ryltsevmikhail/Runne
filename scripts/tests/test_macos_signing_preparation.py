import plistlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.macos_signing.commands import build_sign_command, build_verify_command
from scripts.macos_signing.evidence import normalize_evidence, validate_production_evidence
from scripts.macos_signing.execution import execution_records
from scripts.macos_signing.models import CommandResult, CommandSpec, Disposition, EvidenceDispositions, ExecutionMode, FailureCode, SigningFailure, SigningProfile, Status
from scripts.macos_signing.parsers import parse_codesign_result, parse_notary_result
from scripts.macos_signing.policy import map_tool_status, parse_profile
from scripts.macos_signing.runner import LiveRunner
from scripts.macos_signing.validation import revalidate_candidate, validate_entitlements, validate_request
from scripts.macos_signing import normalize_outcome, prepare_signing
from scripts.tests import macos_signing_case_support, macos_signing_support
from scripts.tests import macos_signing_observation_support
class MacOSSigningPreparationTests(unittest.TestCase):
    def test_production_without_credentials_blocks_without_runner_discovery(self) -> None:
        runner = macos_signing_support.RecordingRunner()
        with mock.patch.multiple("scripts.macos_signing.workflow", validate_request=mock.DEFAULT, build_sign_command=mock.DEFAULT, build_verify_command=mock.DEFAULT, candidate_identity=mock.DEFAULT, build_development_evidence=mock.DEFAULT) as blocked:
            for profile_ref in (None, "SYNTHETIC-OPAQUE-PROFILE-REF"):
                with self.subTest(profile_ref=profile_ref):
                    outcome = prepare_signing(macos_signing_support.missing_production_request(profile_ref), runner, "darwin")
                    self.assertEqual((outcome.failure.code, outcome.disposition), (FailureCode.BLOCKED_CREDENTIALS, Disposition.BLOCKED_CREDENTIALS))
                    self.assertEqual(runner.commands, [])
            for dependency in blocked.values():
                dependency.assert_not_called()
        exit_code, payload, stderr, runner_called, process_called = macos_signing_support.run_production_wrapper()
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["failure"]["code"], "BLOCKED_CREDENTIALS")
        self.assertNotIn("credential-marker", stderr)
        self.assertFalse(runner_called)
        self.assertFalse(process_called)

    def test_non_macos_production_is_unsupported_and_blocked_platform(self) -> None:
        runner = macos_signing_support.RecordingRunner()
        with mock.patch.multiple("scripts.macos_signing.workflow", validate_request=mock.DEFAULT, build_sign_command=mock.DEFAULT, build_verify_command=mock.DEFAULT, candidate_identity=mock.DEFAULT, build_development_evidence=mock.DEFAULT) as blocked:
            outcome = prepare_signing(macos_signing_support.missing_production_request(None), runner, "linux")
            self.assertEqual((outcome.failure.code, outcome.disposition), (FailureCode.UNSUPPORTED_PLATFORM, Disposition.BLOCKED_PLATFORM))
            self.assertEqual(runner.commands, [])
        for dependency in blocked.values():
            dependency.assert_not_called()
    def test_missing_absolute_tool_maps_to_tool_unavailable(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(); self.addCleanup(temporary_directory.cleanup)
        command = CommandSpec("verify-app", "/usr/bin/codesign", ("--verify", "Contents/MacOS/GOCODE"), ".")
        with (
            mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=False),
            mock.patch("scripts.macos_signing.runner.subprocess.run") as run,
        ):
            result = LiveRunner(Path(temporary_directory.name)).run(command)
        self.assertEqual(parse_codesign_result(result), FailureCode.TOOL_UNAVAILABLE)
        run.assert_not_called()

    def test_fake_signing_order_is_daemon_then_app(self) -> None:
        request, runner = macos_signing_support.development_request_and_runner()
        outcome = prepare_signing(request, runner, "darwin")
        self.assertEqual([command.phase for command in runner.commands], ["sign-daemon", "verify-daemon", "sign-app", "verify-app"])
        self.assertEqual((outcome.status, outcome.disposition), (Status.AD_HOC_PREPARED, Disposition.DEVELOPMENT_ONLY))
        macos_signing_case_support.assert_development_runner_boundary(self)
        live_runner = macos_signing_support.RecordingRunner()
        live = prepare_signing(replace(request, execution_mode=ExecutionMode.LIVE), live_runner, "darwin")
        self.assertEqual((live.failure.code, live_runner.commands), (FailureCode.PROFILE_DOWNGRADE_REJECTED, []))
        macos_signing_observation_support.assert_state_snapshots(self)
    def test_production_commands_and_verification_require_hardened_runtime(self) -> None:
        daemon, app = macos_signing_support.make_validated_targets()
        for target, entitlements in ((daemon, Path("daemon.plist")), (app, Path("app.plist"))):
            for command in (
                build_sign_command(target, entitlements, SigningProfile.PRODUCTION_DEVELOPER_ID, "external-identity-reference"),
                build_verify_command(target, SigningProfile.PRODUCTION_DEVELOPER_ID),
            ):
                with self.subTest(phase=command.phase):
                    self.assertNotIn("--deep", command.argv)
                    if command.phase.startswith("sign"):
                        index = command.argv.index("--options")
                        self.assertEqual(command.argv[index + 1], "runtime")
                    if command.phase.startswith("verify"):
                        self.assertEqual(command.argv, ("--verify", "--strict", target.relative_path))
        for builder, args in (
            (build_sign_command, (app, Path("app.plist"), "production-developer-id", "reference")),
            (build_verify_command, (app, "production-developer-id")),
        ):
            with self.subTest(profile=builder.__name__), self.assertRaises(ValueError):
                builder(*args)
        for token in (Path("/host/daemon.plist"), Path("../daemon.plist"), Path("nested/daemon.plist"), Path("app.plist"), Path("other.plist")):
            with self.subTest(entitlements=token), self.assertRaises(ValueError):
                build_sign_command(daemon, token, SigningProfile.DEVELOPMENT_AD_HOC, "-")
        app_bundle = macos_signing_support.make_bundle_target()
        self.assertEqual(build_sign_command(app_bundle, Path("app.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-").argv[-1], "GOCODE.app")
        macos_signing_observation_support.assert_notary_binding_grammar(self)

    def test_error_and_evidence_redact_raw_output_and_credential_marker(self) -> None:
        marker, path = "SYNTHETIC-RAW-MARKER", "/synthetic/raw-output"
        request, failing_runner = macos_signing_support.development_request_and_runner((CommandResult(1, marker + " " + path, marker + " " + path),))
        outcome = prepare_signing(request, failing_runner, "darwin")
        public_json = normalize_outcome(outcome)
        self.assertEqual((outcome.failure.code, outcome.failure.phase), (FailureCode.UNKNOWN_STATUS, "sign-daemon"))
        self.assertEqual(len(failing_runner.commands), 1)
        for raw in (marker.encode(), path.encode()):
            self.assertNotIn(raw, public_json)
        request, success_runner = macos_signing_support.development_request_and_runner((CommandResult(0, marker + " " + path, marker + " " + path),) * 4)
        success = prepare_signing(request, success_runner, "darwin")
        evidence_json = normalize_evidence(success.evidence)
        for raw in (marker.encode(), path.encode()):
            self.assertNotIn(raw, evidence_json)
    def test_live_runner_uses_literal_bounded_argv_without_shell(self) -> None:
        macos_signing_case_support.assert_live_runner_contract(self)
        macos_signing_observation_support.assert_live_notary_artifact_binding(self)
        macos_signing_observation_support.assert_phase_specific_timeouts(self)

    def test_command_spec_rejects_raw_credential_argument(self) -> None:
        for argv in (["--verify"], ("--password",)):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                CommandSpec("test", "/usr/bin/codesign", argv, ".")

    def test_unknown_profile_status_and_tool_output_fail_closed(self) -> None:
        self.assertEqual(parse_profile("unknown-profile").code, FailureCode.UNKNOWN_PROFILE)
        for value in ("unmapped-tool-status", "unmapped-parser-token"):
            with self.subTest(value=value):
                self.assertEqual(map_tool_status(value), FailureCode.UNKNOWN_STATUS)
        for result, expected in ((CommandResult(0, '{"status":"In Progress"}', ""), FailureCode.NOTARIZATION_FAILED), (CommandResult(0, '{"status":"Invalid"}', ""), FailureCode.NOTARIZATION_FAILED), (CommandResult(0, "not-json", ""), FailureCode.UNKNOWN_STATUS)):
            with self.subTest(result=result):
                self.assertEqual(parse_notary_result(result), expected)
        macos_signing_observation_support.assert_notary_submit_contract(self)
        macos_signing_observation_support.assert_production_evidence_provenance(self)

    def test_ad_hoc_or_implicit_bundle_id_fallback_is_rejected(self) -> None:
        self.addCleanup(macos_signing_support.cleanup_request_fixtures)
        request = macos_signing_support.make_request()
        for bundle_id in (None, "dev.gocode.desktop"):
            with self.subTest(bundle_id=bundle_id):
                failure = validate_request(replace(request, profile=SigningProfile.PRODUCTION_DEVELOPER_ID, production_bundle_id=bundle_id))
                self.assertEqual(failure.code, FailureCode.PROFILE_DOWNGRADE_REJECTED)
        for field, value in (("release_candidate_sha256", None), ("release_candidate_sha256", 1), ("release_candidate_sha256", "A" * 64), ("candidate_app", None), ("candidate_app", "not-a-path")):
            with self.subTest(field=field):
                self.assertEqual(validate_request(replace(request, **{field: value})).code, FailureCode.ARTIFACT_NOT_FOUND)
        candidate = request.candidate_app
        macos_signing_support.cleanup_request_fixtures()
        self.assertFalse(candidate.exists())
        macos_signing_observation_support.assert_real_code_directory_contract(self)

    def test_entitlements_are_distinct_empty_plists(self) -> None:
        entitlements = Path(__file__).parents[1] / "macos_signing" / "entitlements"
        app_path, daemon_path = entitlements / "app.plist", entitlements / "daemon.plist"
        self.assertNotEqual(app_path, daemon_path)
        self.assertEqual(plistlib.loads(app_path.read_bytes()), {})
        self.assertEqual(plistlib.loads(daemon_path.read_bytes()), {})
        self.assertNotIsInstance(validate_entitlements(app_path, daemon_path), SigningFailure)
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        source, hard_link = Path(temporary_directory.name) / "app-source.plist", Path(temporary_directory.name) / "app-hard-link.plist"
        source.write_bytes(plistlib.dumps({}))
        hard_link.hardlink_to(source)
        failure = validate_entitlements(source, hard_link)
        self.assertIsInstance(failure, SigningFailure)
        self.assertEqual(failure.code, FailureCode.ENTITLEMENTS_MISMATCH)
        temporary_directory, candidate, _, daemon_entitlements = macos_signing_support.make_candidate()
        self.addCleanup(temporary_directory.cleanup)
        trusted = Path(temporary_directory.name) / "trusted-app.plist"
        trusted.write_bytes(plistlib.dumps({}))
        (candidate / "app.plist").write_bytes(plistlib.dumps({"unexpected": True}))
        captured = validate_request(replace(macos_signing_support.make_request(), candidate_app=candidate, app_entitlements=trusted, daemon_entitlements=daemon_entitlements))
        self.assertEqual(captured.app_entitlements.canonical_path, trusted.resolve())
        command = build_sign_command(macos_signing_support.make_bundle_target(), Path("app.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", captured.app_entitlements)
        with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            LiveRunner(candidate.parent).run(command)
        self.assertEqual(run.call_args.args[0][5], str(trusted.resolve()))
        trusted.write_bytes(plistlib.dumps({"changed": True}))
        with mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True), mock.patch("scripts.macos_signing.runner.os.access", return_value=True), mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
            result = LiveRunner(candidate.parent).run(command)
        self.assertEqual(parse_codesign_result(result), FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        run.assert_not_called()
        macos_signing_case_support.assert_entitlement_binding_contract(self)

    def test_unexpected_entitlements_are_rejected(self) -> None:
        self.addCleanup(macos_signing_support.cleanup_request_fixtures)
        request = macos_signing_support.make_request()
        request.app_entitlements.write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True}))
        self.assertEqual(validate_entitlements(request.app_entitlements, request.daemon_entitlements).code, FailureCode.ENTITLEMENTS_MISMATCH)

    def test_unsigned_or_replaced_sidecar_is_rejected(self) -> None:
        self.addCleanup(macos_signing_support.cleanup_request_fixtures)
        actions = ("missing_daemon", "unsigned_daemon", "candidate_symlink", "contents_symlink", "macos_symlink", "main_symlink", "daemon_symlink", "extra_executable", "missing_main", "non_executable_main")
        for action in actions:
            with self.subTest(action=action):
                request = macos_signing_support.mutate_candidate(macos_signing_support.make_request(), action)
                self.assertEqual(validate_request(request).code, FailureCode.ARTIFACT_NOT_FOUND)
                macos_signing_support.cleanup_request_fixtures()
        request = macos_signing_support.make_request()
        daemon = request.candidate_app / "Contents" / "MacOS" / "gocoded"
        captured = validate_request(request)
        daemon.write_bytes(b"replaced synthetic daemon executable\n")
        self.assertEqual(revalidate_candidate(request.candidate_app, captured).code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        macos_signing_support.cleanup_request_fixtures()
        for relative in ("Resources/fixture.txt", "Info.plist"):
            with self.subTest(relative=relative):
                request = macos_signing_support.make_request()
                captured = validate_request(request)
                (request.candidate_app / "Contents" / relative).write_bytes(b"changed bundle entry\n")
                self.assertEqual(revalidate_candidate(request.candidate_app, captured).code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
                macos_signing_support.cleanup_request_fixtures()

    def test_development_evidence_is_rejected_for_production(self) -> None:
        candidate, signature, evidence = macos_signing_support.development_evidence_from_golden()
        failure = validate_production_evidence(evidence, candidate, signature, "darwin", macos_signing_support.expected_target())
        self.assertEqual(failure.code, FailureCode.PROFILE_DOWNGRADE_REJECTED)

    def test_wrong_team_or_bundle_is_rejected(self) -> None:
        candidate, signature, evidence = macos_signing_support.production_evidence()
        target = macos_signing_support.expected_target()
        for field in ("team_identifier", "bundle_id", "authority_class", "designated_requirement"):
            with self.subTest(field=field):
                invalid = macos_signing_support.replace_evidence_signature(evidence, field, "wrong-value")
                failure = validate_production_evidence(invalid, candidate, signature, "darwin", target)
                self.assertEqual(failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        equivalent = replace(signature, designated_requirement=" identifier  com.example.gocode ")
        self.assertEqual(validate_production_evidence(evidence, candidate, equivalent, "darwin", target).code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        for platform, expected in (("linux", target), ("darwin", macos_signing_support.replace_target(target, main="other"))):
            with self.subTest(platform=platform):
                self.assertEqual(validate_production_evidence(evidence, candidate, signature, platform, expected).code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        macos_signing_observation_support.assert_checked_observation_contract(self)

    def test_changed_sha256_or_cdhash_is_rejected(self) -> None:
        candidate, signature, evidence = macos_signing_support.production_evidence()
        for field, value in (("main_sha256", "f" * 64), ("cdhash", "0" * 40)):
            with self.subTest(field=field):
                invalid = macos_signing_support.replace_evidence_identity(evidence, field, value)
                failure = validate_production_evidence(invalid, candidate, signature, "darwin", macos_signing_support.expected_target())
                self.assertEqual(failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)

    def test_replayed_or_replaced_candidate_cannot_reuse_evidence(self) -> None:
        macos_signing_case_support.assert_replay_and_tree_rejection(self)
        macos_signing_case_support.assert_evidence_cross_binding(self)

    def test_missing_production_notarization_is_rejected(self) -> None:
        candidate, signature, evidence = macos_signing_support.production_evidence()
        invalid = macos_signing_support.replace_evidence_disposition(evidence, notarization="")
        failure = validate_production_evidence(invalid, candidate, signature, "darwin", macos_signing_support.expected_target())
        self.assertEqual(failure.code, FailureCode.NOTARIZATION_NOT_RUN)
        for phase, code in (("staple-validate", FailureCode.STAPLE_NOT_RUN), ("gatekeeper", FailureCode.GATEKEEPER_ASSESSMENT_FAILED)):
            with self.subTest(phase=phase):
                invalid = macos_signing_support.remove_execution(evidence, phase)
                self.assertEqual(validate_production_evidence(invalid, candidate, signature, "darwin", macos_signing_support.expected_target()).code, code)
        for field, code in (("stapling", FailureCode.STAPLE_NOT_RUN), ("gatekeeper", FailureCode.GATEKEEPER_ASSESSMENT_FAILED)):
            with self.subTest(field=field):
                invalid = macos_signing_support.replace_evidence_disposition(evidence, **{field: ""})
                self.assertEqual(validate_production_evidence(invalid, candidate, signature, "darwin", macos_signing_support.expected_target()).code, code)
        invalid = macos_signing_support.replace_execution(evidence, 0, operation="forged")
        self.assertEqual(validate_production_evidence(invalid, candidate, signature, "darwin", macos_signing_support.expected_target()).code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        invalid = macos_signing_support.replace_execution(evidence, 0, hardened_runtime=False)
        self.assertEqual(validate_production_evidence(invalid, candidate, signature, "darwin", macos_signing_support.expected_target()).code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        forged = CommandSpec("sign-daemon", "/usr/bin/codesign", ("--verify", "--strict", "synthetic-GOCODE.app/Contents/MacOS/gocoded"), ".")
        with self.subTest(forged_phase_argv=forged.argv), self.assertRaises(ValueError):
            execution_records((forged,), (CommandResult(0, "", ""),), macos_signing_support.expected_target())
        invalid = replace(evidence, entitlements=replace(evidence.entitlements, app_sha256="f" * 64))
        self.assertEqual(validate_production_evidence(invalid, candidate, signature, "darwin", macos_signing_support.expected_target()).code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)

    def test_fake_success_remains_development_only(self) -> None:
        request, runner = macos_signing_support.development_request_and_runner()
        outcome = prepare_signing(request, runner, "darwin")
        self.assertEqual(len(runner.commands), 4)
        self.assertEqual(outcome.disposition, Disposition.DEVELOPMENT_ONLY)
        self.assertEqual(outcome.status, Status.AD_HOC_PREPARED)
        self.assertFalse(hasattr(Status, "PRODUCTION_READY"))
        candidate, signature, evidence = macos_signing_support.production_evidence()
        crafted = replace(evidence, disposition="OBSERVED_RECORDS")
        for item in (evidence, crafted):
            with self.subTest(disposition=item.disposition):
                self.assertEqual(validate_production_evidence(item, candidate, signature, "darwin", macos_signing_support.expected_target()).code, FailureCode.BLOCKED_CREDENTIALS)

    def test_identical_fixture_inputs_produce_identical_evidence(self) -> None:
        first = macos_signing_support.development_evidence()
        second = macos_signing_support.development_evidence()
        self.assertEqual(normalize_evidence(first), normalize_evidence(second))
        self.assertEqual(normalize_evidence(first), macos_signing_support.golden_evidence_bytes())
        macos_signing_observation_support.assert_actual_development_golden(self)
        production = normalize_evidence(macos_signing_support.production_evidence()[2])
        self.assertIn(b'"phase":"notary-submit"', production)
        self.assertNotIn(b'"notary-status"', production)
        self.assertNotIn(b"opaque-notary-reference", production)
        with self.assertRaises(ValueError):
            normalize_evidence(macos_signing_support.replace_evidence_disposition(macos_signing_support.production_evidence()[2], notarization="raw-output"))
