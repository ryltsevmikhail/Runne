"""Draft 2020-12 schema loading and small stdlib-only fixture validator."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SCHEMA_FILES = {
    "gocode.rc0.schema.candidate-record/3": "rc0-candidate-record-v3.schema.json",
    "gocode.rc0.schema.source-gate-results/3": "rc0-source-gate-results-v3.schema.json",
    "gocode.rc0.schema.test-inventory/3": "rc0-test-inventory-v3.schema.json",
    "gocode.rc0.schema.security-validation/3": "rc0-security-validation-v3.schema.json",
    "gocode.rc0.schema.documentation-validation/3": "rc0-documentation-validation-v3.schema.json",
    "gocode.rc0.schema.fail-closed-disposition/3": "rc0-fail-closed-disposition-v3.schema.json",
    "gocode.rc0.schema.artifact-inventory/3": "rc0-artifact-inventory-v3.schema.json",
    "gocode.rc0.schema.sbom-spdx-2.3/3": "rc0-sbom-spdx-2.3-v3.schema.json",
    "gocode.rc0.schema.checksums-text/3": "rc0-checksums-text-v3.schema.json",
    "gocode.rc0.schema.qualification-policy-bundle/3": "rc0-qualification-policy-bundle-v3.schema.json",
    "gocode.rc0.schema.verification-report/3": "rc0-verification-report-v3.schema.json",
    "gocode.rc0.schema.candidate-record/4": "rc0-candidate-record-v4.schema.json",
    "gocode.rc0.schema.source-gate-results/4": "rc0-source-gate-results-v4.schema.json",
    "gocode.rc0.schema.test-inventory/4": "rc0-test-inventory-v4.schema.json",
    "gocode.rc0.schema.security-validation/4": "rc0-security-validation-v4.schema.json",
    "gocode.rc0.schema.documentation-validation/4": "rc0-documentation-validation-v4.schema.json",
    "gocode.rc0.schema.fail-closed-disposition/4": "rc0-fail-closed-disposition-v4.schema.json",
    "gocode.rc0.schema.artifact-inventory/4": "rc0-artifact-inventory-v4.schema.json",
    "gocode.rc0.schema.sbom-spdx-2.3/4": "rc0-sbom-spdx-2.3-v4.schema.json",
    "gocode.rc0.schema.checksums-text/4": "rc0-checksums-text-v4.schema.json",
    "gocode.rc0.schema.qualification-policy-bundle/4": "rc0-qualification-policy-bundle-v4.schema.json",
    "gocode.rc0.schema.verification-report/4": "rc0-verification-report-v4.schema.json",
}
_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "docs" / "schemas"


def load_schema(schema_id: str) -> dict[str, Any]:
    try:
        path = _SCHEMA_ROOT / SCHEMA_FILES[schema_id]
    except KeyError as error:
        raise ValueError(f"unknown RC0 schema ID: {schema_id}") from error
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("$id") != schema_id:
        raise ValueError(f"schema ID mismatch in {path.name}")
    return schema


def _resolve(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(f"external schema reference is forbidden: {reference}")
    current: Any = root
    for part in reference[2:].split("/"):
        current = current[part.replace("~1", "/").replace("~0", "~")]
    return current


def _kind_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _validate(value: Any, schema: Any, root: dict[str, Any], path: str) -> list[str]:
    if schema is True:
        return []
    if schema is False:
        return [f"{path}: value is forbidden"]
    if "$ref" in schema:
        return _validate(value, _resolve(root, schema["$ref"]), root, path)
    errors: list[str] = []
    expected = schema.get("type")
    if expected and not _kind_matches(value, expected):
        return [f"{path}: expected {expected}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is outside closed enum")
    if isinstance(value, dict):
        required = schema.get("required", [])
        errors.extend(f"{path}: missing required property {key!r}" for key in required if key not in value)
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errors.extend(f"{path}: unknown property {key!r}" for key in value if key not in properties)
        for key, item in value.items():
            if key in properties:
                errors.extend(_validate(item, properties[key], root, f"{path}.{key}"))
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: too few items")
        if len(value) > schema.get("maxItems", 4_096):
            errors.append(f"{path}: too many items")
        if schema.get("uniqueItems"):
            rendered = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(set(rendered)) != len(rendered):
                errors.append(f"{path}: duplicate array item")
        prefix_items = schema.get("prefixItems", [])
        for index, item in enumerate(value):
            item_schema = prefix_items[index] if index < len(prefix_items) else schema.get("items", {})
            errors.extend(_validate(item, item_schema, root, f"{path}[{index}]"))
    elif isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: string is too short")
        pattern = schema.get("pattern")
        if pattern and re.fullmatch(pattern, value) is None:
            errors.append(f"{path}: string does not match {pattern!r}")
    elif isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value):
            errors.append(f"{path}: integer is below minimum")
        if value > schema.get("maximum", value):
            errors.append(f"{path}: integer is above maximum")
    return errors


def validate_schema(record: Any, schema_id: str) -> tuple[str, ...]:
    schema = load_schema(schema_id)
    return tuple(_validate(record, schema, schema, "$"))
