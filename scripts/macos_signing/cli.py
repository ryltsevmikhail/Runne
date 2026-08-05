"""Non-secret command-line entry point for signing preparation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .commands import build_sign_command, build_verify_command, bundle_target, rooted_target
from .models import CommandResult, ExecutionMode, SigningProfile, SigningRequest, ValidatedCandidate
from .runner import FakeRunner
from .validation import validate_request
from .workflow import normalize_outcome, prepare_signing

_ENTITLEMENTS = Path(__file__).with_name("entitlements")
_ZERO_SHA256 = "0" * 64


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_args(argv)
    request = SigningRequest(
        profile=SigningProfile(arguments.profile),
        candidate_app=Path(arguments.candidate_app),
        production_bundle_id=arguments.production_bundle_id,
        app_entitlements=Path(arguments.app_entitlements),
        daemon_entitlements=Path(arguments.daemon_entitlements),
        execution_mode=ExecutionMode.FAKE,
        keychain_profile_ref=None,
        release_candidate_sha256=arguments.release_candidate_sha256,
    )
    runner = FakeRunner((), ()) if request.profile is SigningProfile.PRODUCTION_DEVELOPER_ID else _fake_runner(request)
    outcome = prepare_signing(request, runner, sys.platform)
    sys.stdout.write(normalize_outcome(outcome).decode())
    return 0 if outcome.failure is None else 1


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--profile", required=True, choices=tuple(SigningProfile))
    parser.add_argument("--candidate-app", required=True)
    parser.add_argument("--production-bundle-id")
    parser.add_argument("--app-entitlements", default=_ENTITLEMENTS / "app.plist")
    parser.add_argument("--daemon-entitlements", default=_ENTITLEMENTS / "daemon.plist")
    parser.add_argument("--execution-mode", default=ExecutionMode.FAKE, choices=(ExecutionMode.FAKE,))
    parser.add_argument("--release-candidate-sha256", default=_ZERO_SHA256)
    return parser.parse_args(argv)


def _fake_runner(request: SigningRequest) -> FakeRunner:
    candidate = validate_request(request)
    if not isinstance(candidate, ValidatedCandidate):
        return FakeRunner((), ())
    daemon, app = rooted_target(candidate, candidate.daemon), bundle_target(candidate)
    commands = (
        build_sign_command(daemon, Path("daemon.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", candidate.daemon_entitlements),
        build_verify_command(daemon, SigningProfile.DEVELOPMENT_AD_HOC),
        build_sign_command(app, Path("app.plist"), SigningProfile.DEVELOPMENT_AD_HOC, "-", candidate.app_entitlements),
        build_verify_command(app, SigningProfile.DEVELOPMENT_AD_HOC),
    )
    return FakeRunner(commands, (CommandResult(0, "", ""),) * len(commands))
