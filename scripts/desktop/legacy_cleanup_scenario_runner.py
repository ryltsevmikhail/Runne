"""Historical legacy evidence preflight and structural validation utilities.

ADR-0031: D1.1a has no supported historical file-Keychain source.
The positive legacy_cleanup_scenario_chain dispatch is disabled before native
setup. There is no current native invocation or required legacy CI job.
RUNNE_LEGACY_CLEANUP_EVIDENCE belongs to the retained historical envelope
contract; validating such an envelope never enables import or qualifies D1.1a.
Host checks remain reusable diagnostics, not a supported migration admission.
A future versioned migration profile requires real source provenance and
independent signed isolated native qualification.
"""
from __future__ import annotations

import argparse
import json
import os
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
    with path.open("rb") as source:
        encoded = source.read(MAX_EVIDENCE_BYTES + 1)
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ValueError("oversized evidence")
    return json.loads(encoded, object_pairs_hook=_unique, parse_constant=_invalid_constant)


def host_is_isolated_darwin_arm64() -> bool:
    return (host_platform.system().lower() == "darwin"
            and host_platform.machine().lower() == "arm64")


def icloud_account_present() -> bool:
    """A signed-in iCloud account leaves this preferences plist behind."""
    return (Path.home() / "Library/Preferences/MobileMeAccounts.plist").exists()


def current_user() -> str:
    import pwd

    return pwd.getpwuid(os.getuid()).pw_name


def check_host(isolated_opt_in: bool, expected_user: str = "") -> list[str]:
    if not host_is_isolated_darwin_arm64():
        return ["legacy scenario host is not darwin arm64"]
    if not isolated_opt_in:
        return ["isolated disposable host opt-in is missing"]
    errors: list[str] = []
    if expected_user and current_user() != expected_user:
        errors.append("legacy scenario host user is not the disposable account")
    if icloud_account_present():
        errors.append("legacy scenario host has a signed-in iCloud account")
    return errors


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
    check.add_argument("--expected-user", default="")
    evidence = commands.add_parser("validate-evidence")
    evidence.add_argument("--evidence", type=Path, required=True)
    evidence.add_argument("--candidate-sha256", required=True)
    evidence.add_argument("--tuple-sha256", required=True)
    evidence.add_argument("--workflow-run-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "check-host":
        errors = check_host(args.isolated_host, args.expected_user)
    else:
        errors = validate_evidence_file(
            args.evidence, args.candidate_sha256, args.tuple_sha256, args.workflow_run_id,
        )
    output = {"qualified": False, "structurally_valid": not errors, "errors": errors}
    print(json.dumps(output, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
