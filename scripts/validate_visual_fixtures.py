#!/usr/bin/env python3
"""Validate desktop visual fixture metadata and approved donor goldens."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = ROOT / "docs/07-testing/fixtures/desktop-visual-fixtures.yaml"
DEFAULT_GOLDENS = ROOT / "tests/visual/goldens"

REQUIRED_PROVENANCE_KEYS = {"fixture_id", "donor_commit", "approved"}
OPTIONAL_PROVENANCE_KEYS = {
    "captured_at",
    "os",
    "webview",
    "capture_tool",
    "capture_tool_version",
    "viewport",
    "scale",
    "theme",
    "locale",
    "timezone",
    "clock",
    "target_state",
    "donor_state",
}


def _inline_value(line: str, key: str) -> str | None:
    match = re.search(
        rf"(?:\{{\s*|,\s*){re.escape(key)}:\s*(?:\"([^\"]*)\"|([^,}}]+))",
        line,
    )
    if match is None:
        return None
    return (match.group(1) or match.group(2)).strip()


def _valid_capture_metadata(provenance: dict[str, object]) -> bool:
    if not set(provenance).issubset(REQUIRED_PROVENANCE_KEYS | OPTIONAL_PROVENANCE_KEYS):
        return False
    if "captured_at" in provenance:
        try:
            datetime.fromisoformat(str(provenance["captured_at"]).replace("Z", "+00:00"))
        except ValueError:
            return False
    if "os" in provenance and provenance["os"] not in {"macOS", "Windows", "Linux"}:
        return False
    for key in {"webview", "capture_tool", "capture_tool_version", "locale", "timezone"}:
        if key in provenance and (not isinstance(provenance[key], str) or not provenance[key]):
            return False
    if "viewport" in provenance:
        viewport = provenance["viewport"]
        if (
            not isinstance(viewport, dict)
            or set(viewport) != {"width", "height"}
            or any(not isinstance(value, int) or value <= 0 for value in viewport.values())
        ):
            return False
    if "scale" in provenance and (
        not isinstance(provenance["scale"], int) or provenance["scale"] <= 0
    ):
        return False
    if "theme" in provenance and provenance["theme"] not in {"dark", "light"}:
        return False
    if "clock" in provenance:
        try:
            datetime.fromisoformat(str(provenance["clock"]).replace("Z", "+00:00"))
        except ValueError:
            return False
    return True


def validate_registry(
    registry_path: Path,
    goldens_root: Path,
    *,
    require_goldens: bool,
    capture_target: str | None = None,
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
        fixture_capture_target = _inline_value(line, "capture_target")
        label = fixture_id or "unnamed fixture"
        if fixture_id is None or golden_key is None or donor_path is None or state_data is None:
            errors.append(f"{label}: incomplete visual fixture metadata")
            continue
        if capture_target is not None:
            if fixture_capture_target is None:
                errors.append(f"{fixture_id}: missing capture_target")
                continue
            if fixture_capture_target != capture_target:
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
        if (
            not isinstance(provenance, dict)
            or {key: provenance.get(key) for key in REQUIRED_PROVENANCE_KEYS} != {
            "fixture_id": fixture_id,
            "donor_commit": donor_commit,
            "approved": True,
            }
            or not _valid_capture_metadata(provenance)
        ):
            errors.append(f"{fixture_id}: donor golden provenance mismatch")
    if not fixture_lines:
        errors.append("registry: no visual fixtures")
    return errors


def main() -> int:
    require_goldens = "--require-goldens" in sys.argv
    phase0 = "--phase0" in sys.argv
    capture_target = None
    if "--capture-target" in sys.argv:
        target_index = sys.argv.index("--capture-target") + 1
        if target_index >= len(sys.argv) or sys.argv[target_index].startswith("--"):
            print("ERROR: --capture-target requires a value")
            return 2
        capture_target = sys.argv[target_index]
    registry_path = DEFAULT_REGISTRY
    if phase0:
        registry_path = ROOT / "docs/07-testing/fixtures/desktop-visual-fixtures-phase0.yaml"
    errors = validate_registry(
        registry_path,
        DEFAULT_GOLDENS,
        require_goldens=require_goldens,
        capture_target=capture_target,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    mode = "release goldens" if require_goldens else "fixture metadata"
    labels = ["Phase 0"] if phase0 else []
    if capture_target is not None:
        labels.append(capture_target)
    label = f" ({', '.join(labels)})" if labels else ""
    print(f"Desktop visual {mode}{label} passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
