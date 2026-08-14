"""Restricted front-matter and authority-state checks for governance ADR tests."""

from __future__ import annotations

import re


FRONT_MATTER_KEYS = {
    "title", "status", "document_type", "source_status", "created", "updated", "owners"
}
AUTHORITY_FIELDS = ("owner_domain", "owner_acceptance_state", "owner_acceptance_record")
OWNER_ACCEPTANCE_HEADING = "## Owner acceptance\n"


def parse_scalar(value: str) -> str:
    if re.fullmatch(r'"[^"\\\n]*"', value):
        return value[1:-1]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}|[A-Za-z][A-Za-z0-9_.-]*", value):
        return value
    raise ValueError("front matter has unsupported scalar")


def parse_front_matter(content: str) -> dict[str, object]:
    if "\r" in content or not content.startswith("---\n"):
        raise ValueError("missing exact opening front matter delimiter")
    lines = content.splitlines()
    try:
        end = lines.index("---", 1)
    except ValueError as error:
        raise ValueError("missing exact closing front matter delimiter") from error
    parsed: dict[str, object] = {}
    index = 1
    while index < end:
        match = re.fullmatch(r"([a-z_]+):(.*)", lines[index])
        if not match or match.group(1) in parsed:
            raise ValueError("front matter must use unique known keys")
        key, value = match.groups()
        if key == "owners":
            if value:
                raise ValueError("owners must use explicit list entries")
            index += 1
            owners: list[str] = []
            while index < end and lines[index].startswith("  - "):
                owner = lines[index][4:]
                if not re.fullmatch(r"[a-z0-9-]+", owner):
                    raise ValueError("owners contains invalid value")
                owners.append(owner)
                index += 1
            if not owners:
                raise ValueError("owners must not be empty")
            parsed[key] = owners
            continue
        if not value.startswith(" "):
            raise ValueError("scalar must have one space after colon")
        parsed[key] = parse_scalar(value[1:])
        index += 1
    if set(parsed) != FRONT_MATTER_KEYS:
        raise ValueError("front matter keys do not match the governed shape")
    return parsed


def authority_values(content: str, field: str) -> list[str]:
    return re.findall(rf"(?m)^`{field}`: `([^`]+)`\.$", content)


def visible_status(content: str) -> str:
    runtime = re.findall(r"(?m)^\*\*Status:\*\* (proposed|accepted)$", content)
    desktop = content.split("## Status\n", 1)
    if runtime and len(desktop) == 1 and len(runtime) == 1:
        return runtime[0]
    if not runtime and len(desktop) == 2 and content.count("## Status\n") == 1:
        value = desktop[1].lstrip().splitlines()[0]
        if value in {"Proposed.", "Accepted."}:
            return value[:-1].lower()
    raise ValueError("ADR must have one exact visible status")


def authority_errors(
    content: str, front_matter: dict[str, object], expected_domain: str
) -> list[str]:
    errors: list[str] = []
    if content.count(OWNER_ACCEPTANCE_HEADING) != 1:
        errors.append("ADR must have one owner acceptance section")
        section = ""
    else:
        section = content.split(OWNER_ACCEPTANCE_HEADING, 1)[1].split("\n## ", 1)[0]
    if any(word in content.lower() for word in ("signature", "issuer", "owner_subject_id")):
        errors.append("ADR must not contain inline authority material")
    try:
        disposition = visible_status(content)
    except ValueError as error:
        return errors + [str(error)]
    if front_matter.get("status") != "ready":
        errors.append("front matter status must be ready")
    expected = {
        "proposed": ("pending", "not_recorded"),
        "accepted": ("accepted", "recorded"),
    }.get(disposition)
    if expected is None:
        return errors + ["ADR must have one exact visible status"]
    for field, value in zip(AUTHORITY_FIELDS, (expected_domain, *expected), strict=True):
        if authority_values(content, field) != [value] or authority_values(section, field) != [value]:
            errors.append(f"{field} is missing, duplicate, or contradictory")
    return errors
