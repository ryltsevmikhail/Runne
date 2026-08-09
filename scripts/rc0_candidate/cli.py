"""Fixture-only RC0 candidate CLI with no external authority inputs."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

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
