#!/usr/bin/env python3
"""Validate redacted native credential enrollment evidence without qualifying it."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__:
    from .native_credential_enrollment import linux, macos, windows
else:
    from native_credential_enrollment import linux, macos, windows

SCHEMA_VERSION = "native-credential-enrollment-evidence.v1"
MACOS_ROWS = {"macos-13-arm64.json": "arm64", "macos-13-x86_64.json": "x86_64"}
LINUX_ROWS = {
    "linux-ubuntu-22.04-x86_64-appimage.json": "appimage",
    "linux-ubuntu-22.04-x86_64-deb.json": "deb",
}
WINDOWS_ROWS = {"windows-10-22h2-x86_64-nsis.json": "nsis"}


def validate_evidence(
    value: object, platform: str, expected_tuples: object | None = None
) -> list[str]:
    """Validate an in-memory document or directory of independently-run rows."""
    if isinstance(value, Path):
        return _directory_errors(value, platform, expected_tuples)
    if not isinstance(value, dict):
        return ["evidence is not an object"]
    if value.get("schema_version") != SCHEMA_VERSION or value.get("platform") != platform:
        return ["evidence identity is invalid"]
    rows = value.get("rows")
    if not isinstance(rows, list):
        return ["evidence rows are missing"]
    return _rows_errors(rows, platform, expected_tuples)


def _directory_errors(root: Path, platform: str, expected_tuples: object | None) -> list[str]:
    if platform == "linux":
        return _linux_directory_errors(root, expected_tuples)
    if platform == "windows":
        return _windows_directory_errors(root, expected_tuples)
    if platform != "macos":
        return ["platform is not implemented"]
    rows: list[object] = []
    errors: list[str] = []
    for filename, architecture in MACOS_ROWS.items():
        path = root / filename
        try:
            row = _load_json(path)
        except (OSError, ValueError):
            errors.append(f"missing or malformed evidence row {filename}")
            continue
        if isinstance(row, dict) and row.get("architecture") != architecture:
            errors.append(f"evidence row {filename} has wrong architecture")
        rows.append(row)
    return errors + _rows_errors(rows, platform, expected_tuples)


def _linux_directory_errors(root: Path, expected_tuples: object | None) -> list[str]:
    rows: list[object] = []
    errors: list[str] = []
    for filename, package_format in LINUX_ROWS.items():
        try:
            row = _load_json(root / filename)
        except (OSError, ValueError):
            errors.append(f"missing or malformed evidence row {filename}")
            continue
        if isinstance(row, dict) and row.get("package_format") != package_format:
            errors.append(f"evidence row {filename} has wrong package format")
        rows.append(row)
    return errors + _rows_errors(rows, "linux", expected_tuples)


def _windows_directory_errors(root: Path, expected_tuples: object | None) -> list[str]:
    rows: list[object] = []
    errors: list[str] = []
    for filename, package_format in WINDOWS_ROWS.items():
        try:
            row = _load_json(root / filename)
        except (OSError, ValueError):
            errors.append(f"missing or malformed evidence row {filename}")
            continue
        if isinstance(row, dict) and row.get("package_format") != package_format:
            errors.append(f"evidence row {filename} has wrong package format")
        rows.append(row)
    return errors + _rows_errors(rows, "windows", expected_tuples)


def _rows_errors(rows: list[object], platform: str, expected_tuples: object | None = None) -> list[str]:
    if platform == "macos":
        validator = macos.validate_row
        expected = set(MACOS_ROWS.values())
    elif platform == "linux":
        validator = linux.validate_row
        expected = set(LINUX_ROWS.values())
    elif platform == "windows":
        validator = windows.validate_row
        expected = set(WINDOWS_ROWS.values())
    else:
        return ["platform is not implemented"]
    expected_count = 1 if platform == "windows" else 2
    if len(rows) != expected_count:
        return [f"{platform} evidence must contain exactly {expected_count} independent rows"]
    errors = [error for row in rows for error in validator(row)]
    dimensions = [
        (row.get("architecture") if platform == "macos" else row.get("package_format"))
        for row in rows if isinstance(row, dict)
    ]
    if set(dimensions) != expected or len(dimensions) != len(rows):
        errors.append(f"{platform} evidence dimensions are incomplete or duplicate")
    runs = [row.get("runner", {}).get("workflow_run_id") for row in rows if isinstance(row, dict)]
    if len(runs) != len(set(runs)) or any(not isinstance(run, str) or not run for run in runs):
        errors.append("macOS rows must come from independent protected workflow runs")
    if platform in {"linux", "windows"} and any(
        isinstance(row, dict) and row.get("isolation_class") == "executable_acl" for row in rows
    ):
        errors.append(f"{platform} cannot claim executable ACL isolation")
    if platform == "macos":
        if expected_tuples is None:
            errors.append("expected macOS tuples are required")
        else:
            errors.extend(macos.validate_expected_tuples(expected_tuples, rows))
    elif expected_tuples is not None:
        errors.append("expected tuples are only supported for macOS")
    return errors


def _load_json(path: Path) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    validate = subcommands.add_parser("validate")
    validate.add_argument("--platform", required=True)
    validate.add_argument("--evidence-root", type=Path, required=True)
    validate.add_argument("--expected-tuples", type=Path)
    args = parser.parse_args(argv)
    try:
        expected_tuples = _load_json(args.expected_tuples) if args.expected_tuples else None
    except (OSError, ValueError):
        errors = ["expected tuple binding is missing or malformed"]
    else:
        errors = validate_evidence(args.evidence_root, args.platform, expected_tuples)
    print(json.dumps({"qualified": False, "structurally_valid": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
