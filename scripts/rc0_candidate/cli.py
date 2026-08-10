"""Fixture-only RC0 candidate CLI with no external authority inputs."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from scripts.rc0_policy.canonical import StrictJSONError, loads_canonical

from . import FixtureLocalInputsSummary
from scripts.ci_local_receipt import LocalInputReceiptError, validate_local_input_receipt

_SATISFIED = "FIXTURE_LOCAL_INPUTS_SATISFIED"
_FIELDS = frozenset(
    ("fixture_only", "source_capture", "evidence_construction", "local_command_evidence")
)
_FINAL_FIELDS = frozenset(
    (
        "artifact_construction",
        "fixture_only",
        "fixture_policy",
        "fixture_trust",
        "local_command_evidence",
        "source_capture",
    )
)
_FINAL_COMMAND_IDS = frozenset(
    (
        "architecture.boundary",
        "diff.clean",
        "docs.strict",
        "phase3.exact-tuples",
        "python.focused",
        "rust.focused",
        "source-length.max-300",
        "typescript.focused",
    )
)
_FINAL_OUTPUT = (
    _SATISFIED,
    "RC0_QUALIFIED BLOCKED",
    "PRODUCTION_QUALIFICATION BLOCKED",
    "RELEASE_APPROVAL OUT_OF_SCOPE",
    "PUBLICATION_AUTHORIZATION OUT_OF_SCOPE",
    "EXTERNAL_CAPTURE ACCEPTED_ADRS BLOCKED(INDEPENDENT_VALIDATION_REQUIRED)",
    "EXTERNAL_CAPTURE POLICY BLOCKED(INDEPENDENT_PROVISIONING_REQUIRED)",
    "EXTERNAL_CAPTURE TRUST BLOCKED(INDEPENDENT_PROVISIONING_REQUIRED)",
    "EXTERNAL_CAPTURE ANTI_ROLLBACK BLOCKED(INDEPENDENT_PROVISIONING_REQUIRED)",
    "EXTERNAL_CAPTURE CURRENT_SOURCE BLOCKED(INDEPENDENT_CAPTURE_REQUIRED)",
    "EXTERNAL_CAPTURE RUNNER BLOCKED(INDEPENDENT_PROVISIONING_REQUIRED)",
    "EXTERNAL_INTERFACE docs/release/RC0_TRUST_ROOT_INTERFACE.md",
)
_ROOT = Path(__file__).resolve().parents[2]


def structural_summary(fixture_status: str) -> dict[str, str]:
    """Keep local structural evidence separate from every external authority."""
    local = _SATISFIED if fixture_status == _SATISFIED else "BLOCKED"
    return {
        "fixture_local_inputs": local,
        "production_qualification": "BLOCKED",
        "release_approval": "OUT_OF_SCOPE",
        "publication_authorization": "OUT_OF_SCOPE",
    }


def summarize_fixture_local_inputs(inputs: Mapping[str, Any]) -> FixtureLocalInputsSummary:
    """Require a complete, non-vacuous set of explicitly synthetic local inputs."""
    if not isinstance(inputs, Mapping) or set(inputs) != _FIELDS:
        return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
    commands = inputs.get("local_command_evidence")
    if (
        inputs.get("fixture_only") is not True
        or inputs.get("source_capture") != _SATISFIED
        or inputs.get("evidence_construction") != _SATISFIED
        or not isinstance(commands, list)
        or not commands
    ):
        return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
    identifiers: list[str] = []
    for command in commands:
        if (
            not isinstance(command, dict)
            or set(command) != {"id", "satisfied"}
            or not isinstance(command.get("id"), str)
            or not command["id"]
            or command.get("satisfied") is not True
        ):
            return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
        identifiers.append(command["id"])
    if len(set(identifiers)) != len(identifiers):
        return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
    return FixtureLocalInputsSummary(_SATISFIED)


def summarize_final_dry_run_inputs(
    inputs: Mapping[str, Any],
) -> FixtureLocalInputsSummary:
    """Require every synthetic Task 11 lane without binding a trust identity."""
    if not isinstance(inputs, Mapping) or set(inputs) != _FINAL_FIELDS:
        return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
    for field in (
        "artifact_construction",
        "fixture_policy",
        "fixture_trust",
        "source_capture",
    ):
        if inputs.get(field) != _SATISFIED:
            return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
    if inputs.get("fixture_only") is not True:
        return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
    commands = inputs.get("local_command_evidence")
    if not isinstance(commands, list) or len(commands) != len(_FINAL_COMMAND_IDS):
        return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
    identifiers: list[str] = []
    for command in commands:
        if (
            not isinstance(command, dict)
            or set(command) != {"id", "satisfied"}
            or not isinstance(command.get("id"), str)
            or command.get("satisfied") is not True
        ):
            return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
        identifiers.append(command["id"])
    if set(identifiers) != _FINAL_COMMAND_IDS or len(set(identifiers)) != len(identifiers):
        return FixtureLocalInputsSummary("BLOCKED", "LOCAL_INPUTS_UNAVAILABLE")
    return FixtureLocalInputsSummary(_SATISFIED)


def _load_inputs(
    path: str, mutation_hook: Callable[[str, Path], None] | None = None
) -> Mapping[str, Any] | None:
    candidate = Path(path)
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 65_536:
            return None
        if mutation_hook is not None:
            mutation_hook("after-open", candidate)
        chunks: list[bytes] = []
        remaining = 65_537
        while remaining and (chunk := os.read(descriptor, min(remaining, 1 << 16))):
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        current = os.stat(candidate, follow_symlinks=False)
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns,
        )
        if remaining == 0 or identity(before) != identity(after) or identity(before) != identity(current):
            return None
        try:
            record = loads_canonical(b"".join(chunks))
        except StrictJSONError:
            return None
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return record if isinstance(record, dict) else None


def main(arguments: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if arguments is None else arguments)
    if not arguments:
        sys.stdout.write("BLOCKED(ADR_OR_POLICY_UNAVAILABLE)\n")
        return 2
    if (
        len(arguments) == 7
        and arguments[0] == "fixture-final-dry-run"
        and arguments[1] == "--local-inputs"
        and arguments[3] == "--receipt"
        and arguments[5] == "--inventory"
    ):
        inputs = _load_inputs(arguments[2])
        summary = summarize_final_dry_run_inputs(inputs or {})
        if summary.status != _SATISFIED:
            sys.stdout.write("BLOCKED(LOCAL_INPUTS_UNAVAILABLE)\n")
            return 2
        try:
            validate_local_input_receipt(
                _ROOT,
                Path(arguments[4]),
                Path(arguments[6]),
                consume=True,
            )
        except (LocalInputReceiptError, OSError):
            sys.stdout.write("BLOCKED(LOCAL_INPUTS_UNAVAILABLE)\n")
            return 2
        sys.stdout.write("\n".join(_FINAL_OUTPUT) + "\n")
        return 0
    if (
        len(arguments) == 5
        and arguments[0] == "fixture-local-inputs"
        and arguments[1] == "--receipt"
        and arguments[3] == "--inventory"
    ):
        try:
            validate_local_input_receipt(
                _ROOT,
                Path(arguments[2]),
                Path(arguments[4]),
                consume=True,
            )
        except (LocalInputReceiptError, OSError):
            sys.stdout.write("BLOCKED\n")
            return 2
        sys.stdout.write(_SATISFIED + "\n")
        return 0
    if len(arguments) != 3 or arguments[:2] != ("fixture-dry-run", "--local-inputs"):
        return 2
    inputs = _load_inputs(arguments[2])
    summary = summarize_fixture_local_inputs(inputs or {})
    if summary.status == _SATISFIED:
        sys.stdout.write(_SATISFIED + "\n")
        return 0
    sys.stdout.write(f"BLOCKED({summary.blocked_reason})\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
