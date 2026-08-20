import plistlib
from pathlib import Path

from scripts.macos_signing.commands import (
    build_entitlement_command, build_gatekeeper_command, build_metadata_command,
    build_notary_submit_command, build_requirement_command, build_sign_command,
    build_staple_command, build_verify_command, bundle_target, rooted_target,
)
from scripts.macos_signing.evidence import build_production_evidence_from_results
from scripts.macos_signing.models import CommandResult, SignatureExpectation, SigningProfile
from scripts.macos_signing.state import CandidateStage, CandidateState, bind_notarization_artifact
from scripts.macos_signing.validation import validate_request


def production_evidence(main_bytes=b"synthetic main executable\n", replacement=None):
    from scripts.tests import macos_signing_support

    temporary, candidate, app_entitlements, daemon_entitlements = macos_signing_support.make_candidate("synthetic-Runne.app")
    try:
        (candidate / "Contents" / "MacOS" / "Runne").write_bytes(main_bytes)
        request = macos_signing_support.SigningRequest(SigningProfile.PRODUCTION_DEVELOPER_ID, candidate, "com.example.runne", app_entitlements, daemon_entitlements, macos_signing_support.ExecutionMode.FAKE, None, "0" * 64)
        validated = validate_request(request)
        expectation = SignatureExpectation("com.example.runne", "TEAM000001", "Developer ID Application", "designated => identifier com.example.runne", "c" * 40)
        daemon, app = rooted_target(validated, validated.daemon), bundle_target(validated)
        commands = [command for item, plist, binding in ((daemon, Path("daemon.plist"), validated.daemon_entitlements), (app, Path("app.plist"), validated.app_entitlements)) for command in (build_sign_command(item, plist, SigningProfile.PRODUCTION_DEVELOPER_ID, "external-identity", binding), build_verify_command(item, SigningProfile.PRODUCTION_DEVELOPER_ID), build_metadata_command(item), build_requirement_command(item), build_entitlement_command(item))]
        archive = candidate.parent / "synthetic-GOCODE.zip"
        archive.write_bytes(b"synthetic archive\n")
        binding = bind_notarization_artifact(candidate.parent, archive.name, CandidateState(validated, CandidateStage.APP_SIGNED))
        commands.extend((build_notary_submit_command(binding, "opaque-notary-reference"), build_staple_command(app, "staple"), build_staple_command(app, "validate"), build_gatekeeper_command(app)))
        metadata = "Identifier=com.example.runne\nTeamIdentifier=TEAM000001\nAuthority=Developer ID Application: Synthetic (TEAM000001)\nCDHash=" + "c" * 40 + "\nCodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1+5\n"
        requirement, empty = "designated => identifier com.example.runne\n", plistlib.dumps({}).decode()
        results = [CommandResult(0, empty if command.phase.startswith("entitlements-") else requirement if command.phase.startswith("requirement-") else "", metadata if command.phase.startswith("metadata-") else "") if not command.phase.startswith("notary-") else CommandResult(0, '{"status":"Accepted"}', "") for command in commands]
        if replacement:
            results[next(index for index, command in enumerate(commands) if command.phase == replacement[0])] = replacement[1]
        evidence = build_production_evidence_from_results(CandidateState(validated, CandidateStage.STAPLED), expectation, expectation, "darwin", macos_signing_support.expected_target(), commands, results)
        return CandidateState(validated, CandidateStage.STAPLED), expectation, evidence, tuple(commands), tuple(results), macos_signing_support.expected_target()
    finally:
        temporary.cleanup()
