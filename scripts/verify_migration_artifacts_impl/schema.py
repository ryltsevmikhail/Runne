"""Lightweight Draft 2020-12 schema validation for migration fixtures."""

import re
from typing import Any

from .constants import errors


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
            return True
        ok = type(value) is expected_type
    if not ok:
        errors.append(f"{path}: expected {expected}, got {type(value).__name__}")
    return ok


def validate_enum(value: Any, allowed: list, path: str) -> None:
    if value not in allowed:
        errors.append(f"{path}: value '{value}' not in {allowed}")


def validate_const(value: Any, expected: Any, path: str) -> None:
    if value != expected:
        errors.append(f"{path}: expected const value '{expected}', got '{value}'")


def validate_pattern(value: str, pattern: str, path: str) -> None:
    if not re.match(pattern, value):
        errors.append(f"{path}: '{value}' does not match pattern '{pattern}'")


def validate_minimum(value: int, minimum: int, path: str) -> None:
    if value < minimum:
        errors.append(f"{path}: {value} is less than minimum {minimum}")


def validate_min_length(value: str, min_length: int, path: str) -> None:
    if len(value) < min_length:
        errors.append(f"{path}: length {len(value)} is less than minLength {min_length}")


def validate_property(prop_name: str, value: Any, prop_schema: dict, path: str) -> None:
    """Validate a single property value against its sub-schema."""
    expected_type = prop_schema.get("type")
    if expected_type and not validate_type(value, expected_type, f"{path}.{prop_name}"):
        return
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
        validate_additional_properties(obj, set(properties.keys()), path)
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
        matches = True
        for ckey, cschema in if_entry.get("properties", {}).items():
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
            payload_schema = then_entry.get("properties", {}).get("payload", {})
            if payload_schema:
                base_properties["payload"] = payload_schema
                if "payload" not in base_required:
                    base_required.append("payload")
    merged = dict(schema)
    merged["properties"] = base_properties
    merged["required"] = list(dict.fromkeys(base_required))
    return merged


def validate_against_schema(instance: dict, schema: dict, path: str) -> None:
    """Validate a JSON instance against the migration evidence schema."""
    envelope_props = schema.get("properties", {})
    validate_object(
        instance,
        envelope_props,
        schema.get("required", []),
        schema.get("additionalProperties", None) is False,
        path,
    )
    resolved = resolve_if_then(schema, instance)
    payload_schema = resolved.get("properties", {}).get("payload", {})
    if payload_schema and "payload" in instance:
        validate_object(
            instance["payload"],
            payload_schema.get("properties", {}),
            payload_schema.get("required", []),
            payload_schema.get("additionalProperties", None) is False,
            f"{path}.payload",
        )
