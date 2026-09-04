"""Check legacy evidence structure; never execute native actions or qualify it."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

if __package__:
    from .native_credential_enrollment.legacy_cleanup import validate_evidence
else:
    from native_credential_enrollment.legacy_cleanup import validate_evidence

MAX_EVIDENCE_BYTES = 64 * 1024


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("non-JSON constant")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--tuple-sha256", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    args = parser.parse_args(argv)
    try:
        with args.evidence.open("rb") as source:
            encoded = source.read(MAX_EVIDENCE_BYTES + 1)
        if len(encoded) > MAX_EVIDENCE_BYTES:
            raise ValueError("oversized evidence")
        value = json.loads(encoded, object_pairs_hook=_unique, parse_constant=_invalid_constant)
        errors = validate_evidence(
            value, candidate_sha256=args.candidate_sha256,
            tuple_sha256=args.tuple_sha256, workflow_run_id=args.workflow_run_id,
        )
    except (OSError, ValueError, RecursionError):
        errors = ["legacy evidence is missing, malformed or oversized"]
    print(json.dumps({"qualified": False, "structurally_valid": not errors, "errors": errors}, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
