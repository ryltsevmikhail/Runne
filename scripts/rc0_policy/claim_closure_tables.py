"""Real-shape Markdown table validation for Task 8 claim closure fixtures."""

from __future__ import annotations

import re
from datetime import date


_REGISTRIES = {
    "docs/adr/README.md": (
        ("ADR", "Title", "Status"),
        "ADR",
        "Status",
        "ADR-0027-v1-platform-scope.md",
    ),
    "docs/desktop/adr/README.md": (
        ("ADR", "Решение", "Статус"),
        "ADR",
        "Статус",
        "ADR-0015-v1-platform-scope.md",
    ),
}

_LOGS = {
    "docs/decisions/DECISION_LOG.md": (
        ("Date", "Decision", "ADR", "Status"),
        "ADR",
        "Status",
        "../adr/ADR-0027-v1-platform-scope.md",
    ),
    "docs/desktop/decisions/DECISION_LOG.md": (
        ("Date", "Decision", "Evidence"),
        "Evidence",
        "Decision",
        "../adr/ADR-0015-v1-platform-scope.md",
    ),
}

_OPEN_QUESTIONS = {
    "docs/decisions/OPEN_QUESTIONS.md": (
        ("ID", "Question", "Context", "Raised", "Status", "Resolved by"),
        "OQ-007",
        "Status",
        "Resolved by",
        "Resolved",
        "../adr/ADR-0027-v1-platform-scope.md",
    ),
    "docs/desktop/decisions/OPEN_QUESTIONS.md": (
        ("ID", "Status", "Decision/question", "Gate/resolution"),
        "OQ-005",
        "Status",
        "Gate/resolution",
        "Closed",
        "../adr/ADR-0015-v1-platform-scope.md",
    ),
}

_LOG_STATES = ("Not accepted", "Accepted", "Rejected", "Proposed", "Pending", "Open", "Reopened")
_LOG_STATE_PATTERN = re.compile(
    r"(?<![A-Za-z])(?:" + "|".join(map(re.escape, _LOG_STATES)) + r")(?![A-Za-z])"
)


def validate_closure_table(raw: bytes, path: str, adr: str) -> bool:
    """Validate one of the six owner tables using its actual column roles."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    if path in _REGISTRIES:
        headers, identity, status, target = _REGISTRIES[path]
        rows = _one_table(text, headers)
        return rows is not None and _registry(rows, headers, identity, status, adr, target)
    if path in _LOGS:
        headers, identity, state_column, target = _LOGS[path]
        rows = _one_table(text, headers)
        return rows is not None and _decision_log(rows, headers, identity, state_column, adr, target)
    if path in _OPEN_QUESTIONS:
        headers, oq_id, status, resolution, terminal, target = _OPEN_QUESTIONS[path]
        rows = _one_table(text, headers)
        return rows is not None and _open_question(rows, headers, oq_id, status, resolution, terminal, adr, target)
    return False


def _registry(rows, headers, identity, status, adr, target) -> bool:
    by_name = _columns(headers)
    matches = [row for row in rows if _reference(row[by_name[identity]], adr, target, bare=False)]
    return len(matches) == 1 and _plain(matches[0][by_name[status]]) == "Accepted"


def _decision_log(rows, headers, identity, state_column, adr, target) -> bool:
    by_name = _columns(headers)
    matches = [row for row in rows if _reference(row[by_name[identity]], adr, target, bare=True)]
    if not matches or not _ordered_dates(matches, by_name["Date"]):
        return False
    states = [_log_state(row[by_name[state_column]], state_column == "Decision") for row in matches]
    return (
        all(state is not None for state in states)
        and states.count("Accepted") == 1
        and states[-1] == "Accepted"
        and all(state == "Proposed" for state in states[:-1])
    )


def _open_question(rows, headers, oq_id, status, resolution, terminal, adr, target) -> bool:
    by_name = _columns(headers)
    matches = [row for row in rows if row[by_name["ID"]] == oq_id]
    return (
        len(matches) == 1
        and _plain(matches[0][by_name[status]]) == terminal
        and _reference(matches[0][by_name[resolution]], adr, target, bare=True)
    )


def _one_table(text: str, expected_headers: tuple[str, ...]):
    matches = [rows for headers, rows in _tables(text) if headers == expected_headers]
    return matches[0] if len(matches) == 1 else None


def _tables(text: str):
    lines = text.splitlines()
    result = []
    index = 0
    while index + 1 < len(lines):
        headers = _cells(lines[index])
        divider = _cells(lines[index + 1])
        if headers is None or divider is None or len(headers) != len(divider) or not all(_divider(cell) for cell in divider):
            index += 1
            continue
        rows = []
        index += 2
        while index < len(lines):
            row = _cells(lines[index])
            if row is None or len(row) != len(headers):
                break
            rows.append(row)
            index += 1
        result.append((headers, tuple(rows)))
    return tuple(result)


def _cells(line: str) -> tuple[str, ...] | None:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return None
    return tuple(cell.strip() for cell in stripped[1:-1].split("|"))


def _divider(cell: str) -> bool:
    core = cell.removeprefix(":").removesuffix(":")
    return len(core) >= 3 and set(core) == {"-"}


def _columns(headers: tuple[str, ...]) -> dict[str, int]:
    return {name: index for index, name in enumerate(headers)}


def _reference(cell: str, adr: str, target: str, *, bare: bool) -> bool:
    return (bare and cell == adr) or cell == f"[{adr}]({target})"


def _plain(cell: str) -> str:
    for marker in ("**", "__"):
        if cell.startswith(marker) and cell.endswith(marker) and len(cell) > len(marker) * 2:
            return cell[len(marker) : -len(marker)]
    return cell


def _log_state(cell: str, embedded: bool) -> str | None:
    value = _plain(cell)
    if not embedded:
        return value if value in _LOG_STATES else None
    matches = tuple(_LOG_STATE_PATTERN.finditer(value))
    if len(matches) != 1 or matches[0].start() != 0:
        return None
    state = matches[0].group()
    return state if value.startswith(state + " ") else None


def _ordered_dates(rows: list[tuple[str, ...]], column: int) -> bool:
    try:
        values = [date.fromisoformat(row[column]) for row in rows]
    except ValueError:
        return False
    return values == sorted(values)
