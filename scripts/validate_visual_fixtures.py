#!/usr/bin/env python3
"""Validate desktop visual fixture metadata and approved donor goldens."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = ROOT / "docs/07-testing/fixtures/desktop-visual-fixtures.yaml"
DEFAULT_GOLDENS = ROOT / "tests/visual/goldens"


def _inline_value(line: str, key: str) -> str | None:
    match = re.search(
        rf"(?:\{{\s*|,\s*){re.escape(key)}:\s*(?:\"([^\"]*)\"|([^,}}]+))",
        line,
    )
    if match is None:
        return None
    return (match.group(1) or match.group(2)).strip()


def validate_registry(
    registry_path: Path,
    goldens_root: Path,
    *,
    require_goldens: bool,
) -> list[str]:
    content = registry_path.read_text(encoding="utf-8")
    commit_match = re.search(r"^\s+commit:\s*(\S+)\s*$", content, re.MULTILINE)
    if commit_match is None:
        return ["registry: missing pinned donor commit"]
    donor_commit = commit_match.group(1)
    errors: list[str] = []
    fixture_lines = [
        line.strip()
        for line in content.splitlines()
        if line.lstrip().startswith("- {")
    ]
    for line in fixture_lines:
        fixture_id = _inline_value(line, "id")
        golden_key = _inline_value(line, "golden_key")
        donor_path = _inline_value(line, "donor_path")
        state_data = _inline_value(line, "state_data")
        label = fixture_id or "unnamed fixture"
        if fixture_id is None or golden_key is None or donor_path is None or state_data is None:
            errors.append(f"{label}: incomplete visual fixture metadata")
            continue
        if not require_goldens:
            continue
        golden_path = goldens_root / f"{golden_key}.png"
        provenance_path = golden_path.with_suffix(".png.provenance.json")
        if not golden_path.is_file() or not provenance_path.is_file():
            errors.append(f"{fixture_id}: missing approved donor golden {golden_key}.png")
            continue
        try:
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            errors.append(f"{fixture_id}: invalid donor golden provenance")
            continue
        if provenance != {
            "fixture_id": fixture_id,
            "donor_commit": donor_commit,
            "approved": True,
        }:
            errors.append(f"{fixture_id}: donor golden provenance mismatch")
    if not fixture_lines:
        errors.append("registry: no visual fixtures")
    return errors


def main() -> int:
    require_goldens = "--require-goldens" in sys.argv
    errors = validate_registry(
        DEFAULT_REGISTRY,
        DEFAULT_GOLDENS,
        require_goldens=require_goldens,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    mode = "release goldens" if require_goldens else "fixture metadata"
    print(f"Desktop visual {mode} passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
