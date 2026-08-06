import json
import re
import unittest
from dataclasses import asdict
from pathlib import Path

from scripts.release_v2.manifest import assemble_manifest, manifest_bytes
from scripts.tests.test_release_v2_manifest import _input


class SchemaValidationError(ValueError):
    pass


_KEYWORDS = frozenset(("$schema", "$id", "$defs", "$ref", "title", "type", "required", "additionalProperties", "properties", "const", "enum", "items", "minItems", "minimum", "pattern"))
_TYPES = frozenset(("object", "array", "string", "integer", "null"))


def _validate(root: dict[str, object], value: object) -> None:
    _validate_schema_shape(root, root, set())
    _validate_schema(root, value, root)


def _validate_schema(schema: object, value: object, root: dict[str, object]) -> None:
    if type(schema) is not dict or set(schema) - _KEYWORDS:
        raise SchemaValidationError("unsupported schema")
    if "$ref" in schema:
        _validate_schema(_local_ref(schema["$ref"], root), value, root)
        return
    if "type" in schema and not _matches_type(schema["type"], value):
        raise SchemaValidationError("wrong type")
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        raise SchemaValidationError("wrong constant")
    if "enum" in schema and not any(type(value) is type(item) and value == item for item in _list(schema["enum"])):
        raise SchemaValidationError("wrong enum")
    if type(value) is dict:
        _validate_object(schema, value, root)
    if type(value) is list:
        if "minItems" in schema and (type(schema["minItems"]) is not int or schema["minItems"] < 0):
            raise SchemaValidationError("invalid minItems")
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise SchemaValidationError("too few items")
        if "items" in schema:
            for item in value:
                _validate_schema(schema["items"], item, root)
    if type(value) is int and "minimum" in schema and value < schema["minimum"]:
        raise SchemaValidationError("below minimum")
    if type(value) is str and "pattern" in schema and re.search(schema["pattern"], value) is None:
        raise SchemaValidationError("wrong pattern")


def _validate_schema_shape(schema: object, root: dict[str, object], visited: set[int]) -> None:
    if type(schema) is not dict or set(schema) - _KEYWORDS:
        raise SchemaValidationError("unsupported schema")
    if id(schema) in visited:
        return
    visited.add(id(schema))
    if "$defs" in schema:
        for value in _dict(schema["$defs"]).values():
            _validate_schema_shape(value, root, visited)
    if "properties" in schema:
        for value in _dict(schema["properties"]).values():
            _validate_schema_shape(value, root, visited)
    if "items" in schema:
        _validate_schema_shape(schema["items"], root, visited)
    if "$ref" in schema:
        _validate_schema_shape(_local_ref(schema["$ref"], root), root, visited)


def _validate_object(schema: dict[str, object], value: dict[str, object], root: dict[str, object]) -> None:
    properties = _dict(schema.get("properties", {}))
    required = _list(schema.get("required", []))
    if not all(type(name) is str and name in value for name in required):
        raise SchemaValidationError("required field missing")
    if schema.get("additionalProperties") is not False or set(value) - set(properties):
        raise SchemaValidationError("unexpected property")
    for name, property_schema in properties.items():
        if name in value:
            _validate_schema(property_schema, value[name], root)


def _local_ref(reference: object, root: dict[str, object]) -> object:
    if type(reference) is not str or not reference.startswith("#/$defs/") or "/" in reference[8:]:
        raise SchemaValidationError("unsupported reference")
    return _dict(root.get("$defs", {})).get(reference[8:]) or _missing_ref()


def _missing_ref() -> object:
    raise SchemaValidationError("unknown reference")


def _matches_type(expected: object, value: object) -> bool:
    types = (expected,) if type(expected) is str else tuple(_list(expected))
    if not types or any(type(name) is not str or name not in _TYPES for name in types):
        raise SchemaValidationError("unsupported type")
    return any((name == "object" and type(value) is dict) or (name == "array" and type(value) is list) or (name == "string" and type(value) is str) or (name == "integer" and type(value) is int) or (name == "null" and value is None) for name in types)


def _dict(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise SchemaValidationError("invalid schema object")
    return value


def _list(value: object) -> list[object]:
    if type(value) is not list:
        raise SchemaValidationError("invalid schema array")
    return value


class SchemaTests(unittest.TestCase):
    def test_runtime_fixtures_match_closed_schemas(self) -> None:
        manifest = assemble_manifest(_input())
        fixtures = {
            "release-manifest-v2.schema.json": json.loads(manifest_bytes(manifest)),
            "release-evidence-v1.schema.json": {"schema_version": "qualification-evidence.v1", "qualification_subject_sha256": manifest.inputs.subject.subject_sha256, "records": [asdict(record) for record in manifest.inputs.evidence_records]},
            "release-archive-index-v1.schema.json": manifest.inputs.archive_index.as_dict(),
            "release-claim-matrix-v1.schema.json": {"schema_version": "release-claim-matrix.v1", "subject_sha256": manifest.claims.subject_sha256, "claims": [asdict(claim) for claim in manifest.claims.claims]},
        }
        for name, value in fixtures.items():
            with self.subTest(name=name):
                runtime = json.loads(json.dumps(value))
                _validate(self._schema(name), runtime)
                for invalid in (self._unknown(runtime), self._wrong_type(runtime)):
                    with self.assertRaises(SchemaValidationError):
                        _validate(self._schema(name), invalid)

    def test_nested_value_failing_local_reference_is_rejected(self) -> None:
        manifest = assemble_manifest(_input())
        value = {"schema_version": "qualification-evidence.v1", "qualification_subject_sha256": manifest.inputs.subject.subject_sha256, "records": [asdict(record) for record in manifest.inputs.evidence_records]}
        value["records"][0]["review"]["owner"] = 1
        with self.assertRaises(SchemaValidationError):
            _validate(self._schema("release-evidence-v1.schema.json"), value)

    def test_unknown_schema_keyword_is_rejected(self) -> None:
        with self.assertRaises(SchemaValidationError):
            _validate({"type": "string", "minLength": 1}, "value")

    def test_empty_runtime_mandatory_arrays_are_rejected(self) -> None:
        manifest = assemble_manifest(_input())
        fixtures = {
            "release-manifest-v2.schema.json": json.loads(manifest_bytes(manifest)),
            "release-evidence-v1.schema.json": {"schema_version": "qualification-evidence.v1", "qualification_subject_sha256": manifest.inputs.subject.subject_sha256, "records": [asdict(record) for record in manifest.inputs.evidence_records]},
            "release-archive-index-v1.schema.json": manifest.inputs.archive_index.as_dict(),
            "release-claim-matrix-v1.schema.json": {"schema_version": "release-claim-matrix.v1", "subject_sha256": manifest.claims.subject_sha256, "claims": [asdict(claim) for claim in manifest.claims.claims]},
        }
        cases = (
            ("release-manifest-v2.schema.json", "qualification_evidence_sha256s", fixtures["release-manifest-v2.schema.json"]),
            ("release-evidence-v1.schema.json", "records", fixtures["release-evidence-v1.schema.json"]),
            ("release-evidence-v1.schema.json", "checks", fixtures["release-evidence-v1.schema.json"]["records"][0]),
            ("release-archive-index-v1.schema.json", "entries", fixtures["release-archive-index-v1.schema.json"]),
            ("release-claim-matrix-v1.schema.json", "claims", fixtures["release-claim-matrix-v1.schema.json"]),
        )
        for name, field, parent in cases:
            with self.subTest(name=name, field=field):
                invalid = json.loads(json.dumps(fixtures[name]))
                if parent is fixtures["release-evidence-v1.schema.json"]["records"][0]:
                    invalid["records"][0][field] = []
                else:
                    invalid[field] = []
                with self.assertRaises(SchemaValidationError):
                    _validate(self._schema(name), invalid)

    def test_min_items_without_items_rejects_empty_array(self) -> None:
        schema = {"type": "array", "minItems": 1}
        with self.assertRaises(SchemaValidationError):
            _validate(schema, [])
        _validate(schema, [1])

    def test_schema_preflight_rejects_unknown_keyword_in_optional_property(self) -> None:
        schema = {"type": "object", "additionalProperties": False, "properties": {"optional": {"type": "string", "minLength": 1}}}
        with self.assertRaises(SchemaValidationError):
            _validate(schema, {})

    def test_schema_preflight_rejects_unknown_local_ref_in_optional_property(self) -> None:
        schema = {"type": "object", "additionalProperties": False, "properties": {"optional": {"$ref": "#/$defs/missing"}}}
        with self.assertRaises(SchemaValidationError):
            _validate(schema, {})

    @staticmethod
    def _schema(name: str) -> dict[str, object]:
        return json.loads((Path(__file__).parents[2] / "docs" / "schemas" / name).read_text(encoding="utf-8"))

    @staticmethod
    def _unknown(value: dict[str, object]) -> dict[str, object]:
        result = dict(value)
        result["unexpected"] = True
        return result

    @staticmethod
    def _wrong_type(value: dict[str, object]) -> dict[str, object]:
        result = dict(value)
        result[next(iter(result))] = 1
        return result
