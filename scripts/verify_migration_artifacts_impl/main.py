"""Command-line orchestration for migration artifact verification."""

from __future__ import annotations

import json
import os

from .checks import check_blacklist, check_source_sha
from .constants import BASELINE_SHA, errors, warnings
from .io import display_path, load_json, parse_args, verify_digest_sidecar
from .schema import validate_against_schema


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    schema_path = args.schema
    golden_dir = args.golden_dir

    if not os.path.exists(schema_path):
        errors.append(f"Schema not found: {schema_path}")
        return print_summary(2)
    try:
        schema = load_json(schema_path)
    except json.JSONDecodeError as error:
        errors.append(f"Invalid JSON in schema: {error}")
        return print_summary(2)

    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"Schema $schema is not Draft 2020-12: {schema.get('$schema')}")
    if not schema.get("$id"):
        errors.append("Schema missing $id")
    if schema.get("type") != "object":
        errors.append("Schema top-level type must be 'object'")
    if not os.path.isdir(golden_dir):
        errors.append(f"Golden directory not found: {golden_dir}")
        return print_summary(2)

    golden_files = sorted(
        filename
        for filename in os.listdir(golden_dir)
        if filename.endswith(".json") and not filename.endswith(".digest")
    )
    if not golden_files:
        errors.append(f"No golden files found in {golden_dir}")
        return print_summary(2)

    print("=== GOCODE Migration Artifact Verifier ===")
    print(f"Baseline SHA: {BASELINE_SHA[:12]}")
    print(f"Schema: {display_path(schema_path)}")
    print(f"Golden dir: {display_path(golden_dir)}\n")

    for filename in golden_files:
        json_path = os.path.join(golden_dir, filename)
        rel = display_path(json_path)
        print(f"{rel}:")
        try:
            instance = load_json(json_path)
        except json.JSONDecodeError as error:
            errors.append(f"{rel}: invalid JSON - {error}")
            continue
        validate_against_schema(instance, schema, rel)
        check_source_sha(instance, rel)
        check_blacklist(instance, rel)
        verify_digest_sidecar(json_path, instance)
        print()
    return print_summary(1 if errors else 0)


def print_summary(exit_code: int) -> int:
    print(f"Errors:   {len(errors)}")
    print(f"Warnings: {len(warnings)}")
    if errors:
        print("\nERRORS:")
        for error in errors:
            print(f"  - {error}")
    if warnings:
        print("\nWARNINGS:")
        for warning in warnings:
            print(f"  - {warning}")
    if not errors and not warnings:
        print("\nOK All checks passed.")
    elif not errors:
        print("\nOK No errors (warnings only).")
    return exit_code
