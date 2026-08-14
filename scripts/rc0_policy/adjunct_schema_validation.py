"""Strict, bounded Draft 2020-12 subset for the nineteen adjunct schemas."""

from __future__ import annotations

import re
from typing import Any

from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes, loads_canonical


class AdjunctSchemaValidationError(ValueError):
    """A supplied adjunct schema is outside the closed supported subset."""


_ROOT_KEYS = {"$schema", "$id", "title", "$defs"}
_KEYS = {"$ref", "anyOf", "type", "const", "enum", "additionalProperties", "required", "maxProperties", "properties", "minItems", "maxItems", "uniqueItems", "items", "minLength", "maxLength", "pattern", "minimum", "maximum"}
_TYPES = {"object", "array", "string", "integer", "boolean", "null"}
_DRAFT = "https://json-schema.org/draft/2020-12/schema"


def parse_adjunct_schema(raw: bytes, schema_id: str) -> dict[str, Any]:
    if type(raw) is not bytes or type(schema_id) is not str:
        raise TypeError("adjunct schema bytes and ID are required")
    try:
        schema = loads_canonical(raw)
    except StrictJSONError as error:
        raise AdjunctSchemaValidationError("schema bytes are invalid") from error
    if type(schema) is not dict or schema.get("$id") != schema_id:
        raise AdjunctSchemaValidationError("schema ID does not match provisioned bytes")
    if schema.get("$schema") != _DRAFT or type(schema.get("title")) is not str:
        raise AdjunctSchemaValidationError("root schema metadata is invalid")
    _check_schema(schema, schema, True, ())
    return schema


def validate_adjunct_schema_instance(schema: object, value: object) -> tuple[str, ...]:
    if type(schema) is not dict:
        raise TypeError("adjunct schema must be an object")
    _check_schema(schema, schema, True, ())
    return tuple(_validate(value, schema, schema, "$"))


def _reference(root: dict[str, Any], reference: object, trail: tuple[str, ...]) -> dict[str, Any]:
    if type(reference) is not str or not reference.startswith("#/$defs/") or "/" in reference[8:]:
        raise AdjunctSchemaValidationError("reference must name a local definition")
    if reference in trail:
        raise AdjunctSchemaValidationError("local reference cycle")
    definitions = root.get("$defs")
    if type(definitions) is not dict:
        raise AdjunctSchemaValidationError("local definitions are invalid")
    value = definitions.get(reference[8:])
    if type(value) is not dict:
        raise AdjunctSchemaValidationError("local reference is missing")
    return value


def _nonnegative(value: object, name: str) -> None:
    if type(value) is not int or value < 0:
        raise AdjunctSchemaValidationError(f"{name} must be a non-negative integer")


def _integer(value: object, name: str) -> None:
    if type(value) is not int:
        raise AdjunctSchemaValidationError(f"{name} must be an integer")


def _context(schema: dict[str, Any], keywords: set[str], expected: str) -> None:
    if set(schema) & keywords and schema.get("type") != expected:
        raise AdjunctSchemaValidationError(f"{expected} keyword outside its schema context")


def _check_schema(schema: object, root: dict[str, Any], is_root: bool, trail: tuple[str, ...]) -> None:
    if type(schema) is not dict:
        raise AdjunctSchemaValidationError("schema position must be an object")
    allowed = _KEYS | (_ROOT_KEYS if is_root else set())
    if set(schema) - allowed:
        raise AdjunctSchemaValidationError("unsupported schema keyword")
    if is_root and (
        ("$schema" in schema and schema["$schema"] != _DRAFT)
        or ("$id" in schema and type(schema["$id"]) is not str)
        or ("title" in schema and type(schema["title"]) is not str)
    ):
        raise AdjunctSchemaValidationError("root schema metadata is invalid")
    if "$ref" in schema:
        reference = schema["$ref"]
        _check_schema(_reference(root, reference, trail), root, False, trail + (reference,))
    if "anyOf" in schema:
        branches = schema["anyOf"]
        if type(branches) is not list or not branches:
            raise AdjunctSchemaValidationError("anyOf must be non-empty")
        for branch in branches:
            _check_schema(branch, root, False, trail)
    if "type" in schema and (type(schema["type"]) is not str or schema["type"] not in _TYPES):
        raise AdjunctSchemaValidationError("unsupported type")
    if "enum" in schema and (type(schema["enum"]) is not list or not schema["enum"]):
        raise AdjunctSchemaValidationError("enum must be non-empty")
    if "const" in schema:
        canonical_bytes(schema["const"])
    if "enum" in schema:
        for item in schema["enum"]:
            canonical_bytes(item)
        if len({canonical_bytes(item) for item in schema["enum"]}) != len(schema["enum"]):
            raise AdjunctSchemaValidationError("enum must be unique")
    for name in ("minItems", "maxItems", "maxProperties", "minLength", "maxLength"):
        if name in schema:
            _nonnegative(schema[name], name)
    for name in ("minimum", "maximum"):
        if name in schema:
            _integer(schema[name], name)
    if "minimum" in schema and "maximum" in schema and schema["minimum"] > schema["maximum"]:
        raise AdjunctSchemaValidationError("integer bounds are invalid")
    _context(schema, {"additionalProperties", "required", "maxProperties", "properties"}, "object")
    _context(schema, {"minItems", "maxItems", "uniqueItems", "items"}, "array")
    _context(schema, {"minLength", "maxLength", "pattern"}, "string")
    _context(schema, {"minimum", "maximum"}, "integer")
    if "additionalProperties" in schema and schema["additionalProperties"] is not False:
        raise AdjunctSchemaValidationError("only closed objects are supported")
    if "required" in schema and (type(schema["required"]) is not list or any(type(name) is not str for name in schema["required"]) or len(set(schema["required"])) != len(schema["required"])):
        raise AdjunctSchemaValidationError("required must be unique strings")
    if "properties" in schema:
        if type(schema["properties"]) is not dict:
            raise AdjunctSchemaValidationError("properties must be an object")
        if any(type(name) is not str for name in schema["properties"]):
            raise AdjunctSchemaValidationError("property names must be strings")
        for child in schema["properties"].values():
            _check_schema(child, root, False, trail)
    if "items" in schema:
        _check_schema(schema["items"], root, False, trail)
    if "uniqueItems" in schema and type(schema["uniqueItems"]) is not bool:
        raise AdjunctSchemaValidationError("uniqueItems must be boolean")
    if "pattern" in schema:
        if type(schema["pattern"]) is not str:
            raise AdjunctSchemaValidationError("pattern must be string")
        try: re.compile(schema["pattern"])
        except re.error as error: raise AdjunctSchemaValidationError("invalid pattern") from error
    if is_root and "$defs" in schema:
        if type(schema["$defs"]) is not dict:
            raise AdjunctSchemaValidationError("definitions must be an object")
        if any(type(name) is not str for name in schema["$defs"]):
            raise AdjunctSchemaValidationError("definition names must be strings")
        for child in schema["$defs"].values():
            _check_schema(child, root, False, trail)


def _type(value: object, expected: str) -> bool:
    return {"object": type(value) is dict, "array": type(value) is list, "string": type(value) is str, "integer": type(value) is int, "boolean": type(value) is bool, "null": value is None}[expected]


def _equal(left: object, right: object) -> bool:
    return canonical_bytes(left) == canonical_bytes(right)


def _validate(value: object, schema: dict[str, Any], root: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    if "$ref" in schema:
        errors += _validate(value, _reference(root, schema["$ref"], ()), root, path)
    if "anyOf" in schema:
        if not any(not _validate(value, item, root, path) for item in schema["anyOf"]):
            errors.append(f"{path}: outside anyOf")
    if "type" in schema and not _type(value, schema["type"]): errors.append(f"{path}: wrong type")
    if "const" in schema and not _equal(value, schema["const"]): errors.append(f"{path}: const")
    if "enum" in schema and not any(_equal(value, item) for item in schema["enum"]): errors.append(f"{path}: enum")
    if type(value) is dict:
        props = schema.get("properties", {})
        errors += [f"{path}: required" for key in schema.get("required", []) if key not in value]
        if schema.get("additionalProperties") is False: errors += [f"{path}: extra" for key in value if key not in props]
        if "maxProperties" in schema and len(value) > schema["maxProperties"]: errors.append(f"{path}: properties")
        for key, item in value.items():
            if key in props: errors += _validate(item, props[key], root, f"{path}.{key}")
    elif type(value) is list:
        if len(value) < schema.get("minItems", 0) or ("maxItems" in schema and len(value) > schema["maxItems"]): errors.append(f"{path}: items")
        if schema.get("uniqueItems") and len({canonical_bytes(item) for item in value}) != len(value): errors.append(f"{path}: duplicate")
        if "items" in schema:
            for index, item in enumerate(value): errors += _validate(item, schema["items"], root, f"{path}[{index}]")
    elif type(value) is str:
        if len(value) < schema.get("minLength", 0) or ("maxLength" in schema and len(value) > schema["maxLength"]): errors.append(f"{path}: length")
        if "pattern" in schema and re.search(schema["pattern"], value) is None: errors.append(f"{path}: pattern")
    elif type(value) is int and not schema.get("minimum", value) <= value <= schema.get("maximum", value): errors.append(f"{path}: range")
    return errors
