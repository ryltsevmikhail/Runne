"""Fixture-only RC0 candidate CLI with no external authority inputs."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from scripts.rc0_policy.canonical import StrictJSONError, loads_canonical

from . import FixtureLocalInputsSummary

_SATISFIED = "FIXTURE_LOCAL_INPUTS_SATISFIED"
_FIELDS = frozenset(
    ("fixture_only", "source_capture", "evidence_construction", "local_command_evidence")
)


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


def _load_inputs(path: str) -> Mapping[str, Any] | None:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        return None
    try:
        record = loads_canonical(candidate.read_bytes())
    except (OSError, StrictJSONError):
        return None
    return record if isinstance(record, dict) else None


def main(arguments: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if arguments is None else arguments)
    if not arguments:
        sys.stdout.write("BLOCKED(ADR_OR_POLICY_UNAVAILABLE)\n")
        return 2
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
