"""Offline schema reference for the SourceCraft legacy evidence enforcer.

The qualification workflow invokes the runner-owned wrapper at
``/opt/gocode/sourcecraft/bin/sourcecraft-native-package-evidence-enforce``;
this candidate-checkout module is never an active trust boundary. It documents
the exact checks the wrapper must add for ``legacy-source-cleanup-evidence.v1``
on top of the structural validation already performed in-checkout: the
signature over the envelope bytes, the repository, workflow, protected ref and
candidate binding, and the runner identity attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

if __package__:
    from .native_credential_enrollment.legacy_cleanup import validate_evidence
else:
    from native_credential_enrollment.legacy_cleanup import validate_evidence

SCHEMA = "legacy-source-cleanup-evidence.v1"
EXPECTED_REPOSITORY = "https://git@git.sourcecraft.dev/ryltsevmg/runne.git"
EXPECTED_WORKFLOW = "desktop-qualification"
EXPECTED_SOURCE_REF = "refs/tags/v1.0.0"


def _sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def structural_errors(value: object, *, candidate_sha256: str, tuple_sha256: str,
                      workflow_run_id: str) -> list[str]:
    """Structural checks the checkout validator already performs."""
    return validate_evidence(
        value, candidate_sha256=candidate_sha256,
        tuple_sha256=tuple_sha256, workflow_run_id=workflow_run_id,
    )


def enforcer_contract(source_digest: str, repository: str, workflow: str,
                      source_ref: str) -> list[str]:
    """Protected-context checks the runner-owned wrapper must enforce beyond
    the structural layer: the exact repository, the manual-only qualification
    workflow, the immutable protected ref, and a valid runner signature over
    the envelope bytes (implemented runner-side against the trust root)."""
    errors: list[str] = []
    if repository != EXPECTED_REPOSITORY:
        errors.append("legacy evidence repository does not match")
    if workflow != EXPECTED_WORKFLOW:
        errors.append("legacy evidence workflow does not match")
    if source_ref != EXPECTED_SOURCE_REF:
        errors.append("legacy evidence source ref is not the protected tag")
    if not _sha(source_digest):
        errors.append("legacy evidence source digest is invalid")
    return errors


def candidate_binding(commit_sha: str, run_id: str) -> tuple[str, str, str]:
    """The exact binding derivation used by the qualification task."""
    candidate = hashlib.sha256(
        f"runne-legacy-cleanup-candidate\037{commit_sha}".encode()
    ).hexdigest()
    tuple_digest = hashlib.sha256(
        f"runne-legacy-cleanup-tuple\037{commit_sha}\037{run_id}".encode()
    ).hexdigest()
    return candidate, tuple_digest, run_id


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--tuple-sha256", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    args = parser.parse_args(argv)
    try:
        value = json.loads(args.evidence.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("legacy evidence reference: evidence is unreadable", file=sys.stderr)
        return 1
    errors = structural_errors(
        value, candidate_sha256=args.candidate_sha256,
        tuple_sha256=args.tuple_sha256, workflow_run_id=args.workflow_run_id,
    )
    print("legacy evidence reference is structural-only; the runner-owned",
          "enforcer adds signature, repository, workflow, ref and runner",
          "identity checks", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
