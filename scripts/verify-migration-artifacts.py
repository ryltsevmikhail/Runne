#!/usr/bin/env python3
"""GOCODE Runtime L3 Golden Migration Artifact Verifier.

Validates migration evidence fixtures in docs/golden/migration/ against
docs/schemas/migration-evidence-v1.schema.json (JSON Schema Draft 2020-12).

Performs:
  1. Load and parse the JSON Schema.
  2. Validate every docs/golden/migration/*.json against the schema.
  3. Enforce source_sha == BASELINE_SHA.
  4. Reject blacklisted keys (secret, token, prompt, etc.).
  5. Verify sha256 digest of JCS-canonicalized bytes against .digest sidecar.
  6. Never overwrite artifacts.

Usage:
    python3 scripts/verify-migration-artifacts.py [--golden-dir PATH] [--schema PATH]
"""

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(BASE, "docs", "schemas", "migration-evidence-v1.schema.json")
GOLDEN_DIR = os.path.join(BASE, "docs", "golden", "migration")
BASELINE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

BLACKLIST_KEYS = {
    "secret", "token", "prompt", "authorization", "cookie",
    "user_id", "taskrun_id", "path_raw",
}

errors: list[str] = []
warnings: list[str] = []


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--golden-dir",
        default=GOLDEN_DIR,
        help="directory containing migration JSON fixtures (default: %(default)s)",
    )
    parser.add_argument(
        "--schema",
        default=SCHEMA_PATH,
        help="migration evidence JSON Schema path (default: %(default)s)",
    )
    return parser.parse_args(argv)


# ── JCS canonicalization (RFC 8785 subset) ──────────────────────────────

def jcs_canonicalize(obj: Any) -> bytes:
    """Serialize a JSON value in canonical form (sorted keys, no whitespace, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_digest(obj: Any) -> str:
    """Compute sha256:<hex> of JCS-canonicalized bytes."""
    return "sha256:" + hashlib.sha256(jcs_canonicalize(obj)).hexdigest()


# ── Lightweight Draft 2020-12 validator ─────────────────────────────────

def validate_required(obj: dict, required: list[str], path: str) -> None:
    for key in required:
        if key not in obj:
            errors.append(f"{path}: missing required field '{key}'")


def validate_additional_properties(obj: dict, allowed: set[str], path: str) -> None:
    for key in obj:
        if key not in allowed:
            errors.append(f"{path}: unexpected property '{key}' (additionalProperties: false)")


def validate_type(value: Any, expected: str, path: str) -> bool:
    if expected == "integer":
        ok = type(value) is int
    elif expected == "number":
        ok = type(value) in (int, float)
    else:
        type_map = {
            "string": str,
            "boolean": bool,
            "object": dict,
            "array": list,
        }
        expected_type = type_map.get(expected)
        if expected_type is None:
            return True  # unknown type, skip
        ok = type(value) is expected_type
    if not ok:
        errors.append(f"{path}: expected {expected}, got {type(value).__name__}")
    return ok


def validate_enum(value: Any, allowed: list, path: str) -> None:
    if value not in allowed:
        errors.append(f"{path}: value '{value}' not in {allowed}")


def validate_const(value: Any, expected: Any, path: str) -> None:
    if value != expected:
        errors.append(
            f"{path}: expected const value '{expected}', got '{value}'"
        )


def validate_pattern(value: str, pattern: str, path: str) -> None:
    if not re.match(pattern, value):
        errors.append(f"{path}: '{value}' does not match pattern '{pattern}'")


def validate_minimum(value: int, minimum: int, path: str) -> None:
    if value < minimum:
        errors.append(f"{path}: {value} is less than minimum {minimum}")


def validate_min_length(value: str, min_length: int, path: str) -> None:
    if len(value) < min_length:
        errors.append(
            f"{path}: length {len(value)} is less than minLength {min_length}"
        )


def validate_property(prop_name: str, value: Any, prop_schema: dict, path: str) -> None:
    """Validate a single property value against its sub-schema."""
    expected_type = prop_schema.get("type")
    if expected_type:
        if not validate_type(value, expected_type, f"{path}.{prop_name}"):
            return  # type mismatch, stop validation for this prop

    if "enum" in prop_schema:
        validate_enum(value, prop_schema["enum"], f"{path}.{prop_name}")

    if "const" in prop_schema:
        validate_const(value, prop_schema["const"], f"{path}.{prop_name}")

    if "pattern" in prop_schema and isinstance(value, str):
        validate_pattern(value, prop_schema["pattern"], f"{path}.{prop_name}")

    if "minimum" in prop_schema and isinstance(value, int):
        validate_minimum(value, prop_schema["minimum"], f"{path}.{prop_name}")

    if "minLength" in prop_schema and isinstance(value, str):
        validate_min_length(value, prop_schema["minLength"], f"{path}.{prop_name}")

    # Recurse for nested objects
    if isinstance(value, dict) and "properties" in prop_schema:
        validate_object(
            value,
            prop_schema.get("properties", {}),
            prop_schema.get("required", []),
            prop_schema.get("additionalProperties", None) is False,
            f"{path}.{prop_name}",
        )


def validate_object(
    obj: dict,
    properties: dict,
    required: list[str],
    closed: bool,
    path: str,
) -> None:
    """Validate an object against its schema definition."""
    validate_required(obj, required, path)

    if closed:
        allowed = set(properties.keys())
        validate_additional_properties(obj, allowed, path)

    for prop_name, prop_schema in properties.items():
        if prop_name in obj:
            validate_property(prop_name, obj[prop_name], prop_schema, path)


def resolve_if_then(schema: dict, instance: dict) -> dict:
    """Resolve allOf if/then blocks to collect payload requirements."""
    base_properties = dict(schema.get("properties", {}))
    base_required = list(schema.get("required", []))

    for entry in schema.get("allOf", []):
        if_entry = entry.get("if", {})
        then_entry = entry.get("then", {})

        if not if_entry or not then_entry:
            continue

        # Check if condition matches
        cond_props = if_entry.get("properties", {})
        matches = True
        for ckey, cschema in cond_props.items():
            if ckey not in instance:
                matches = False
                break
            if "const" in cschema and instance[ckey] != cschema["const"]:
                matches = False
                break
            if "enum" in cschema and instance[ckey] not in cschema["enum"]:
                matches = False
                break

        if matches:
            # Merge payload sub-schema from then
            payload_schema = then_entry.get("properties", {}).get("payload", {})
            if payload_schema:
                payload_required = payload_schema.get("required", [])
                base_properties["payload"] = payload_schema
                if "payload" not in base_required:
                    base_required.append("payload")
                # Extend required with payload sub-fields for validation
                base_required = list(dict.fromkeys(base_required))  # dedupe

    merged = dict(schema)
    merged["properties"] = base_properties
    merged["required"] = base_required
    return merged


def validate_against_schema(instance: dict, schema: dict, path: str) -> None:
    """Validate a JSON instance against the migration evidence schema."""
    # Step 1: validate envelope
    envelope_props = schema.get("properties", {})
    envelope_required = schema.get("required", [])
    envelope_closed = schema.get("additionalProperties", None) is False

    validate_object(instance, envelope_props, envelope_required, envelope_closed, path)

    # Step 2: resolve if/then for payload shape
    resolved = resolve_if_then(schema, instance)
    payload_schema = resolved.get("properties", {}).get("payload", {})
    if payload_schema and "payload" in instance:
        payload = instance["payload"]
        payload_props = payload_schema.get("properties", {})
        payload_required = payload_schema.get("required", [])
        payload_closed = payload_schema.get("additionalProperties", None) is False

        validate_object(
            payload, payload_props, payload_required, payload_closed, f"{path}.payload"
        )


# ── Blacklist check ────────────────────────────────────────────────────

def check_blacklist(obj: Any, path: str = "$") -> None:
    """Recursively check for blacklisted keys."""
    if isinstance(obj, dict):
        for key in obj:
            if key.lower() in BLACKLIST_KEYS:
                errors.append(f"{path}: blacklisted key '{key}' found")
            check_blacklist(obj[key], f"{path}.{key}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            check_blacklist(item, f"{path}[{i}]")


# ── Source SHA enforcement ─────────────────────────────────────────────

def check_source_sha(instance: dict, path: str) -> None:
    """Ensure source_sha matches the pinned baseline."""
    actual = instance.get("source_sha")
    if actual != BASELINE_SHA:
        errors.append(
            f"{path}: source_sha '{actual}' does not match baseline "
            f"'{BASELINE_SHA}'"
        )


# ── Digest verification ────────────────────────────────────────────────

def verify_digest_sidecar(json_path: str, instance: dict) -> None:
    """Compare JCS-canonical digest against .digest sidecar."""
    digest_path = json_path + ".digest"
    if not os.path.exists(digest_path):
        errors.append(f"{os.path.relpath(json_path, BASE)}: missing .digest sidecar")
        return

    expected = open(digest_path).read().strip()
    actual = compute_digest(instance)

    if actual != expected:
        errors.append(
            f"{os.path.relpath(json_path, BASE)}: digest mismatch — "
            f"expected {expected}, computed {actual}"
        )
    else:
        print(f"  ✓ digest matches: {actual}")


# ── Main ────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    schema_path = args.schema
    golden_dir = args.golden_dir

    # Load schema
    if not os.path.exists(schema_path):
        errors.append(f"Schema not found: {schema_path}")
        return print_summary(2)

    try:
        schema = json.load(open(schema_path))
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON in schema: {e}")
        return print_summary(2)

    # Validate schema itself
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"Schema $schema is not Draft 2020-12: {schema.get('$schema')}")
    if not schema.get("$id"):
        errors.append("Schema missing $id")
    if schema.get("type") != "object":
        errors.append("Schema top-level type must be 'object'")

    # Find golden files
    if not os.path.isdir(golden_dir):
        errors.append(f"Golden directory not found: {golden_dir}")
        return print_summary(2)

    golden_files = sorted(
        f for f in os.listdir(golden_dir) if f.endswith(".json") and not f.endswith(".digest")
    )

    if not golden_files:
        errors.append(f"No golden files found in {golden_dir}")
        return print_summary(2)

    print(f"=== GOCODE Migration Artifact Verifier ===")
    print(f"Baseline SHA: {BASELINE_SHA[:12]}")
    print(f"Schema: {os.path.relpath(schema_path, BASE)}")
    print(f"Golden dir: {os.path.relpath(golden_dir, BASE)}")
    print()

    for filename in golden_files:
        json_path = os.path.join(golden_dir, filename)
        rel = os.path.relpath(json_path, BASE)
        print(f"{rel}:")

        # Load fixture
        try:
            instance = json.load(open(json_path))
        except json.JSONDecodeError as e:
            errors.append(f"{rel}: invalid JSON — {e}")
            continue

        # 1. Schema validation
        validate_against_schema(instance, schema, rel)

        # 2. Source SHA check
        check_source_sha(instance, rel)

        # 3. Blacklist check
        check_blacklist(instance, rel)

        # 4. Digest verification
        verify_digest_sidecar(json_path, instance)

        print()

    return print_summary(1 if errors else 0)


def print_summary(exit_code: int) -> int:
    print(f"Errors:   {len(errors)}")
    print(f"Warnings: {len(warnings)}")

    if errors:
        print(f"\n❌ ERRORS:")
        for e in errors:
            print(f"  • {e}")

    if warnings:
        print(f"\n⚠️ WARNINGS:")
        for w in warnings:
            print(f"  • {w}")

    if not errors and not warnings:
        print("\n✓ All checks passed.")
    elif not errors:
        print("\n✓ No errors (warnings only).")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
