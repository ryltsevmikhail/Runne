"""Command-line entry point for the offline Benchmark V1 verifier."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .aggregate import summarize
from .contract import (
    ContractError,
    load_verified_json,
    load_verified_json_with_digest,
    validate_cohort_envelope,
    validate_profile,
    verify_contract,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the frozen Runne Benchmark V1 contract")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-contract")
    verify.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    summary = subparsers.add_parser("summarize")
    summary.add_argument("--profile", type=pathlib.Path, required=True)
    summary.add_argument("--outcomes", type=pathlib.Path, required=True)
    try:
        arguments = parser.parse_args(argv)
        if arguments.command == "verify-contract":
            result = verify_contract(arguments.root.resolve())
        else:
            profile_path = arguments.profile.resolve()
            profile_value, profile_digest = load_verified_json_with_digest(profile_path)
            profile = validate_profile(profile_value)
            cohort = load_verified_json(arguments.outcomes.resolve())
            outcomes = validate_cohort_envelope(
                cohort,
                profile_digest,
            )
            result = summarize(profile, outcomes)
    except ContractError as error:
        print(f"benchmark-v1: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0
