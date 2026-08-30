import argparse
import json
import sys
from pathlib import Path

from .models import FailureCode, SigningFailure
from .product_models import (
    ProductCandidateRequest,
    ProductSigningOutcome,
    ProductSigningRunRequest,
    ProductSigningStage,
    ProductionCredentialReferences,
)
from .product_orchestration import run_product_signing
from .product_runner import ProductLiveRunner

_ENTITLEMENTS = Path(__file__).parent / "entitlements"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sign and notarize a Runne macOS product")
    parser.add_argument("--candidate-app", required=True, type=Path)
    parser.add_argument("--output-dmg", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--release-candidate-sha256", required=True)
    parser.add_argument("--signing-identity-ref", required=True)
    parser.add_argument("--notary-profile-ref", required=True)
    parser.add_argument("--notary-keychain-ref", required=True, type=Path)
    parser.add_argument(
        "--app-entitlements",
        type=Path,
        default=_ENTITLEMENTS / "product-app.plist",
    )
    parser.add_argument("--cli-entitlements", type=Path, default=_ENTITLEMENTS / "cli.plist")
    parser.add_argument("--daemon-entitlements", type=Path, default=_ENTITLEMENTS / "daemon.plist")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        credentials = ProductionCredentialReferences(
            arguments.signing_identity_ref,
            arguments.notary_profile_ref,
            arguments.notary_keychain_ref,
        )
        candidate = ProductCandidateRequest(
            arguments.candidate_app,
            arguments.release_candidate_sha256,
            arguments.app_entitlements,
            arguments.cli_entitlements,
            arguments.daemon_entitlements,
        )
        request = ProductSigningRunRequest(
            candidate,
            credentials,
            arguments.output_dmg,
            arguments.evidence,
        )
        outcome = run_product_signing(
            request,
            ProductLiveRunner(arguments.candidate_app.parent),
            sys.platform,
        )
    except (TypeError, ValueError):
        outcome = ProductSigningOutcome(
            ProductSigningStage.UNSIGNED_APP,
            SigningFailure(FailureCode.BLOCKED_CREDENTIALS, "credentials", ""),
            None,
        )
    print(normalize_product_outcome(outcome).decode(), end="")
    return 0 if outcome.failure is None else 1


def normalize_product_outcome(outcome: ProductSigningOutcome) -> bytes:
    if not isinstance(outcome, ProductSigningOutcome) or not isinstance(
        outcome.stage, ProductSigningStage
    ):
        raise ValueError("invalid product signing outcome")
    failure = outcome.failure
    if failure is not None and not isinstance(failure, SigningFailure):
        raise ValueError("invalid product signing outcome")
    payload = {
        "stage": outcome.stage.value,
        "failure": None
        if failure is None
        else {"code": failure.code.value, "phase": failure.phase},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
