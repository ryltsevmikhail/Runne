#!/usr/bin/env python3
"""Validate and score the immutable Desktop v1 capability registry."""

import argparse
import json
import os
import sys
from pathlib import Path

from capability_manifest_impl.io import canonical_source_content_digest, clean_source_paths, load_json, sha256_file
from capability_manifest_impl.scoring import QualificationContext, evaluate
from capability_manifest_impl.validation import validate_repository


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATUS = ROOT / "docs/evidence/desktop-v1-capability-status-v1.json"
DEFAULT_DEFINITION = ROOT / "docs/profiles/desktop-v1-capabilities-v1.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--source-ref")
    score = commands.add_parser("score")
    score.add_argument("--status", type=Path, default=DEFAULT_STATUS)
    score.add_argument("--status-provenance", type=Path)
    score.add_argument("--source-ref")
    score.add_argument("--verify-provenance", action="store_true")
    score.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args(argv)
    if args.command == "validate":
        errors = validate_repository(ROOT, verify_source_ref=args.source_ref)
        print(json.dumps({"valid": not errors, "errors": list(errors)}, sort_keys=True))
        return 0 if not errors else 1
    return _score(args)


def _score(args: argparse.Namespace) -> int:
    errors = validate_repository(ROOT)
    if errors:
        print(json.dumps({"valid": False, "errors": list(errors)}, sort_keys=True))
        return 1
    definition = load_json(DEFAULT_DEFINITION)
    status = load_json(args.status)
    qualification = _qualification(args)
    evaluation = evaluate(definition, status, qualification)
    value = {
        "scoreBps": evaluation.score_bps,
        "capabilityStages": list(evaluation.capability_stages),
        "fullyQualified": evaluation.fully_qualified,
        "blockers": list(evaluation.blockers),
    }
    print(json.dumps(value, sort_keys=True) if args.format == "json" else value)
    return 0


def _qualification(args: argparse.Namespace) -> QualificationContext | None:
    if not args.verify_provenance or not args.source_ref or args.status_provenance is None:
        return None
    try:
        bundle = load_json(args.status_provenance)
        if not isinstance(bundle, dict) or set(bundle) != {"status_sha256", "source_content_sha256", "definition_sha256", "verified_gate_ids"}:
            return None
        status = load_json(args.status)
        if not isinstance(status, dict) or os.environ.get("GOCODE_DESKTOP_CAPABILITY_TRUSTED_STATUS_SHA256") != sha256_file(args.status):
            return None
        source_digest = canonical_source_content_digest(ROOT, args.source_ref)
        if bundle["status_sha256"] != sha256_file(args.status) or bundle["source_content_sha256"] != source_digest or bundle["definition_sha256"] != status.get("definition_sha256"):
            return None
        trusted = _trusted_gates(status, bundle.get("verified_gate_ids"))
        if trusted is None:
            return None
        return QualificationContext(
            source_digest, args.source_ref, clean_source_paths(ROOT),
            str(bundle["status_sha256"]), trusted,
        )
    except (OSError, ValueError):
        return None


def _trusted_gates(status: dict[str, object], claimed: object) -> tuple[str, ...] | None:
    """Accept only gate subjects pre-verified by protected CI policy, never a submitted bundle."""

    try:
        policy = json.loads(os.environ["GOCODE_DESKTOP_CAPABILITY_TRUSTED_GATE_PROVENANCE"])
    except (KeyError, json.JSONDecodeError):
        return None
    if not isinstance(policy, dict) or not isinstance(claimed, list) or any(not isinstance(item, str) for item in claimed):
        return None
    rows = {row.get("gate_id"): row for row in status.get("gates", []) if isinstance(row, dict)}
    trusted: list[str] = []
    for gate_id in sorted(claimed):
        row = rows.get(gate_id)
        bound = policy.get(gate_id)
        if not isinstance(row, dict) or row.get("disposition") != "verified" or not isinstance(row.get("provenance"), dict) or bound != row["provenance"]:
            return None
        trusted.append(gate_id)
    return tuple(trusted)


if __name__ == "__main__":
    sys.exit(main())
