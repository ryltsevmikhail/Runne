#!/usr/bin/env python3
"""Run fail-closed YAML front-matter validation for the documentation tree."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

REQUIRED_FIELDS = ("title", "status", "document_type", "source_status", "created", "updated")
ALLOWED_STATUSES = {"draft", "review", "ready", "accepted", "approved", "verified", "superseded", "deprecated"}
DATE_TOKEN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
TOP_LEVEL_FIELD = re.compile(r"^([a-z_]+):(?:[ \t]+(.+))?$")


def _scalar(value: str) -> str:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        try:
            return str(json.loads(value))
        except json.JSONDecodeError:
            return value
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    return value.split(" #", 1)[0].rstrip()


def _front_matter(path: Path) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return {}, [f"{path.name}: cannot read document"]
    if not content.startswith("---\n"):
        return {}, [f"{path.name}: missing YAML front matter"]
    closing = content.find("\n---\n", 4)
    if closing < 0:
        return {}, [f"{path.name}: unterminated YAML front matter"]
    values: dict[str, str] = {}
    for line in content[4:closing].splitlines():
        if not line or line.startswith((" ", "\t")):
            continue
        match = TOP_LEVEL_FIELD.fullmatch(line)
        if match is None:
            errors.append(f"{path.name}: invalid YAML front matter line")
            continue
        key, value = match.groups()
        if key in values:
            errors.append(f"{path.name}: duplicate front matter field {key}")
        values[key] = _scalar(value) if value else ""
    return values, errors


def validate_docs(root: Path) -> list[str]:
    docs_root = root / "docs"
    if not docs_root.is_dir():
        return ["docs: missing documentation tree"]
    errors: list[str] = []
    for path in sorted(docs_root.rglob("*.md")):
        values, parse_errors = _front_matter(path)
        errors.extend(parse_errors)
        for field in REQUIRED_FIELDS:
            if field not in values or not values[field]:
                errors.append(f"{path.name}: missing front matter field {field}")
        if values.get("status") and values["status"] not in ALLOWED_STATUSES:
            errors.append(f"{path.name}: unsupported status {values['status']}")
        dates: dict[str, date] = {}
        for field in ("created", "updated"):
            value = values.get(field, "")
            if not value:
                continue
            if DATE_TOKEN.fullmatch(value) is None:
                errors.append(f"{path.name}: invalid {field} date")
                continue
            try:
                dates[field] = date.fromisoformat(value)
            except ValueError:
                errors.append(f"{path.name}: invalid {field} date")
        if dates.get("updated") and dates.get("created") and dates["updated"] < dates["created"]:
            errors.append(f"{path.name}: updated date is older than created date")
        if dates.get("updated") and dates["updated"] > date.today():
            errors.append(f"{path.name}: updated date is in the future")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    errors = validate_docs(args.root)
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        return 1
    print("Desktop documentation front matter passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
