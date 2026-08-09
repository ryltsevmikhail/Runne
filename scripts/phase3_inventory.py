#!/usr/bin/env python3
"""Fail-closed parser and tuple loader for Phase 3 libtest evidence."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


TEST_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*): test$")
LIST_SUMMARY_RE = re.compile(r"^\d+ tests?, \d+ benchmarks$")
RUNNING_RE = re.compile(r"^running (\d+) tests?$")
RESULT_RE = re.compile(
    r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"\d+ measured; \d+ filtered out; finished in .+$"
)
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PHASE3_IDS = (
    "phase3.evidence-fixtures", "phase3.evidence-shadow-import",
    "phase3.evidence-lineage", "phase3.evidence-rollback",
    "phase3.migration-control", "phase3.migration-rollout", "phase3.migration-sqlite",
    "phase3.migration-routing-sqlite", "phase3.migration-routing",
)


class Phase3InventoryError(ValueError):
    """Libtest output or Phase 3 tuple evidence is not exact."""


@dataclass(frozen=True)
class ExactExecution:
    executed: int
    passed: int
    ignored: int


@dataclass(frozen=True)
class EvidenceTuple:
    package: str
    integration_target: str
    fully_qualified_test_name: str
    source_sha: str
    toolchain: str
    inventory_digest: str


def _decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Phase3InventoryError("libtest output is not valid UTF-8") from error


def parse_libtest_list(raw: bytes) -> tuple[str, ...]:
    """Accept only unique libtest test records and its explicit list summary."""
    names: list[str] = []
    for line in _decode(raw).splitlines():
        if not line or LIST_SUMMARY_RE.fullmatch(line):
            continue
        match = TEST_RE.fullmatch(line)
        if not match:
            raise Phase3InventoryError(f"unexpected libtest list line: {line!r}")
        names.append(match.group(1))
    if not names:
        raise Phase3InventoryError("missing Rust test inventory entries")
    if len(set(names)) != len(names):
        raise Phase3InventoryError("duplicate libtest test entry")
    return tuple(names)


def verify_exact_execution(listing: tuple[str, ...], run: bytes) -> ExactExecution:
    """Require one selected test to execute, pass, and remain non-ignored."""
    if len(listing) != 1:
        raise Phase3InventoryError("exact execution requires exactly one listed selector")
    selector = listing[0]
    expected_test_line = f"test {selector} ... ok"
    running: list[int] = []
    summaries: list[tuple[int, int, int]] = []
    test_lines = 0
    for line in _decode(run).splitlines():
        if not line:
            continue
        if match := RUNNING_RE.fullmatch(line):
            running.append(int(match.group(1)))
        elif line == expected_test_line:
            test_lines += 1
        elif match := RESULT_RE.fullmatch(line):
            summaries.append(tuple(map(int, match.groups())))
        else:
            raise Phase3InventoryError(f"unexpected libtest run line: {line!r}")
    if len(running) != 1 or len(summaries) != 1 or test_lines != 1:
        raise Phase3InventoryError("unparseable exact libtest summary")
    executed = running[0]
    passed, failed, ignored = summaries[0]
    result = ExactExecution(executed, passed, ignored)
    if result != ExactExecution(1, 1, 0) or failed != 0:
        raise Phase3InventoryError("exact execution must be 1 executed, 1 passed, 0 ignored")
    return result


def load_phase3_tuples(document: dict, source_sha: str) -> tuple[tuple[str, EvidenceTuple], ...]:
    """Load all and only the resolved Phase 3 inventory reservations."""
    if not SOURCE_SHA_RE.fullmatch(source_sha):
        raise Phase3InventoryError("invalid source SHA")
    records = {record.get("id"): record for record in document.get("records", [])}
    if set(identifier for identifier in records if str(identifier).startswith("phase3.")) != set(PHASE3_IDS):
        raise Phase3InventoryError("missing or unexpected Phase 3 reservation")
    tuples: list[tuple[str, EvidenceTuple]] = []
    for identifier in PHASE3_IDS:
        record = records[identifier]
        fields = ("package", "integration_target", "fully_qualified_test_name", "toolchain", "list_digest")
        if record.get("selector_status") != "RESOLVED" or not all(isinstance(record.get(field), str) and record[field] for field in fields):
            raise Phase3InventoryError(f"Phase 3 reservation is not resolved: {identifier}")
        digest = record["list_digest"]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise Phase3InventoryError(f"invalid list digest: {identifier}")
        tuples.append((identifier, EvidenceTuple(record["package"], record["integration_target"], record["fully_qualified_test_name"], source_sha, record["toolchain"], digest)))
    return tuple(tuples)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if len(arguments) == 2 and arguments[0] == "list-digest":
            raw = sys.stdin.buffer.read()
            names = parse_libtest_list(raw)
            if names.count(arguments[1]) != 1:
                raise Phase3InventoryError("selector is not exactly one listed test")
            print(hashlib.sha256(raw).hexdigest())
        elif len(arguments) == 2 and arguments[0] == "exact":
            result = verify_exact_execution((arguments[1],), sys.stdin.buffer.read())
            print(f"executed={result.executed} passed={result.passed} ignored={result.ignored}")
        elif len(arguments) == 3 and arguments[0] == "tuples":
            document = json.loads(Path(arguments[1]).read_text(encoding="utf-8"))
            for identifier, item in load_phase3_tuples(document, arguments[2]):
                print("\t".join((identifier, item.package, item.integration_target, item.fully_qualified_test_name, item.source_sha, item.toolchain, item.inventory_digest)))
        else:
            raise Phase3InventoryError("usage: list-digest SELECTOR | exact SELECTOR | tuples INVENTORY SOURCE_SHA")
    except (Phase3InventoryError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
