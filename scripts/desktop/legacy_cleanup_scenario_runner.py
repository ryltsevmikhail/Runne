"""Preflight and evidence gates for the dedicated legacy cleanup scenario.

This module never executes native work itself. The isolated disposable host
runs the pinned in-repo scenario invocation (see the Rust
``legacy_cleanup_scenario_chain`` test) and then asks this module to check the
host preconditions and to structurally validate the produced evidence
envelope. Both modes are fail-closed and never report qualification:
signature verification and protected enforcement remain separate gates.

Pinned scenario invocation (run from the candidate checkout, darwin arm64
disposable user only):

    cargo test -p runne-daemon \
        --test provider_credential_writer_authority \
        --features test-support,desktop-protected \
        --locked legacy_cleanup_scenario_chain -- --exact --ignored \
        legacy_cleanup_scenario_chain_completes_import_cutover_delete_crash_and_tombstone

The scenario reads its binding from ``RUNNE_LEGACY_CLEANUP_CANDIDATE``,
``RUNNE_LEGACY_CLEANUP_TUPLE``, ``RUNNE_LEGACY_CLEANUP_RUN_ID`` and writes the
envelope to ``RUNNE_LEGACY_CLEANUP_EVIDENCE``.
"""
from __future__ import annotations

import argparse
import json
import platform as host_platform
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


def load_evidence(path: Path) -> object:
    encoded = path.read_bytes()[: MAX_EVIDENCE_BYTES + 1]
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ValueError("oversized evidence")
    return json.loads(encoded, object_pairs_hook=_unique, parse_constant=_invalid_constant)


def host_is_isolated_darwin_arm64() -> bool:
    return (host_platform.system().lower() == "darwin"
            and host_platform.machine().lower() == "arm64")


def check_host(isolated_opt_in: bool) -> list[str]:
    if not host_is_isolated_darwin_arm64():
        return ["legacy scenario host is not darwin arm64"]
    if not isolated_opt_in:
        return ["isolated disposable host opt-in is missing"]
    return []


def validate_evidence_file(path: Path, candidate_sha256: str, tuple_sha256: str,
                           workflow_run_id: str) -> list[str]:
    try:
        value = load_evidence(path)
    except (OSError, ValueError, RecursionError):
        return ["legacy evidence is missing, malformed or oversized"]
    return validate_evidence(
        value, candidate_sha256=candidate_sha256,
        tuple_sha256=tuple_sha256, workflow_run_id=workflow_run_id,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check-host")
    check.add_argument("--isolated-host", action="store_true")
    evidence = commands.add_parser("validate-evidence")
    evidence.add_argument("--evidence", type=Path, required=True)
    evidence.add_argument("--candidate-sha256", required=True)
    evidence.add_argument("--tuple-sha256", required=True)
    evidence.add_argument("--workflow-run-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "check-host":
        errors = check_host(args.isolated_host)
    else:
        errors = validate_evidence_file(
            args.evidence, args.candidate_sha256, args.tuple_sha256, args.workflow_run_id,
        )
    output = {"qualified": False, "structurally_valid": not errors, "errors": errors}
    print(json.dumps(output, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
