#!/usr/bin/env python3
"""Non-native macOS qualification planning and structural envelope validation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

if __package__:
    from .native_credential_enrollment import macos
    from .native_credential_enrollment.evidence_io import load_json
    from .native_credential_enrollment.macos_preflight import context_errors, validate_envelope
    from .native_credential_enrollment_probe import validate_evidence
else:
    from native_credential_enrollment import macos
    from native_credential_enrollment.evidence_io import load_json
    from native_credential_enrollment.macos_preflight import context_errors, validate_envelope
    from native_credential_enrollment_probe import validate_evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "validate-envelope"):
        command = commands.add_parser(name)
        command.add_argument("--expected-tuples", required=True, type=Path)
        command.add_argument("--run-context", required=True, type=Path)
        if name == "validate-envelope":
            command.add_argument("--evidence-root", required=True, type=Path)
            command.add_argument("--envelope", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        tuples, context = load_json(args.expected_tuples), load_json(args.run_context)
        errors = macos.validate_expected_tuples(tuples, []) + context_errors(context)
        if not errors and args.command == "validate-envelope":
            errors = validate_evidence(args.evidence_root, "macos", tuples)
            if not errors:
                row = load_json(args.evidence_root / "macos-13-arm64.json")
                errors = validate_envelope(load_json(args.envelope), row, tuples, context)
    except (OSError, ValueError):
        errors = ["required evidence or run context is absent or malformed"]
    print(json.dumps({
        "qualified": False, "native_execution": False,
        "structurally_valid": not errors,
        "external_signature_verification_required": True,
        "errors": errors,
    }, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
