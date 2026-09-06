"""Command-line entry point for the offline Benchmark V1 verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

from .aggregate import summarize
from .contract import (
    ContractError,
    load_verified_json,
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
            profile = validate_profile(load_verified_json(profile_path))
            cohort = load_verified_json(arguments.outcomes.resolve())
            outcomes = validate_cohort_envelope(
                cohort,
                hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            )
            result = summarize(profile, outcomes)
    except ContractError as error:
        print(f"benchmark-v1: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0
