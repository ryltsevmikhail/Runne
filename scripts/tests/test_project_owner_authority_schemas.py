"""Schema vectors for the isolated solo project-owner authority contracts."""

from __future__ import annotations

import json
import re
import unittest
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from scripts.project_owner_authority.schema_semantics import trust_config_errors


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = {
    "trust-config": "project-owner-trust-config-v1.schema.json",
    "receipt": "project-owner-authority-receipt-v1.schema.json",
    "rotation": "project-owner-key-rotation-v1.schema.json",
    "backup-metadata": "project-owner-encrypted-key-backup-v1.schema.json",
}
FIXTURES = ROOT / "scripts/project_owner_authority/fixtures/v1"
REQUIRED_DOCUMENTS = (
    "docs/adr/ADR-0027-v1-platform-scope.md",
    "docs/decisions/v1-platform-scope-v1.json",
)
PROFILE = "gocode.project-owner.v1-platform-scope/1"
PURPOSE = "V1_PLATFORM_SCOPE_AUTHORIZATION"
DOCUMENTS_BY_PROFILE = {(PURPOSE, PROFILE): REQUIRED_DOCUMENTS}
_KEYWORDS = frozenset({"$schema", "$id", "$defs", "$ref", "title", "description", "type", "additionalProperties", "required", "properties", "const", "enum", "minLength", "maxLength", "pattern", "minimum", "maximum", "minItems", "maxItems", "uniqueItems", "items", "prefixItems", "allOf", "if", "then"})
_TYPES = frozenset({"object", "array", "string", "integer", "null"})


def load_fixture(name: str) -> dict:
    """Load one redacted, valid authority fixture by its stable name."""
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _schema(name: str) -> dict:
    return json.loads((ROOT / "docs/schemas" / SCHEMAS[name]).read_text(encoding="utf-8"))


def _matches_type(kind: object, value: object) -> bool:
    kinds = (kind,) if isinstance(kind, str) else tuple(kind) if isinstance(kind, list) else ()
    return any({"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str), "integer": isinstance(value, int) and not isinstance(value, bool), "null": value is None}.get(item, False) for item in kinds)


def _schema_errors(schema: object, root: dict | None = None) -> list[str]:
    if not isinstance(schema, dict):
        return ["schema is not an object"]
    root = schema if root is None else root
    errors = ["unsupported keyword"] if set(schema) - _KEYWORDS else []
    if schema is root and (schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" or not isinstance(schema.get("$id"), str) or not isinstance(schema.get("title"), str) or not isinstance(schema.get("description"), str)):
        errors.append("root metadata")
    if "type" in schema and (not isinstance(schema["type"], str) and not (isinstance(schema["type"], list) and schema["type"] and all(isinstance(item, str) for item in schema["type"])) or not set((schema["type"],) if isinstance(schema["type"], str) else schema["type"]) <= _TYPES):
        errors.append("type")
    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference.startswith("#/$defs/") or reference.removeprefix("#/$defs/") not in root.get("$defs", {}):
            errors.append("reference")
        else:
            errors.extend(_schema_errors(root["$defs"][reference.removeprefix("#/$defs/")], root))
    for child in tuple(schema.get("$defs", {}).values()) + tuple(schema.get("properties", {}).values()) + tuple(schema.get("allOf", ())) + tuple(schema.get("prefixItems", ())):
        errors.extend(_schema_errors(child, root))
    for key in ("if", "then", "items"):
        if key in schema and isinstance(schema[key], dict):
            errors.extend(_schema_errors(schema[key], root))
    return errors


def _errors(schema: object, value: object, root: object | None = None) -> list[str]:
    if not isinstance(schema, dict):
        return ["schema is not an object"]
    root = schema if root is None else root
    if "$ref" in schema:
        target = schema["$ref"]
        if not isinstance(target, str) or not target.startswith("#/$defs/"):
            return ["unsupported reference"]
        siblings = {key: item for key, item in schema.items() if key != "$ref"}
        return _errors(root["$defs"][target.removeprefix("#/$defs/")], value, root) + _errors(siblings, value, root)
    errors: list[str] = []
    if "const" in schema and value != schema["const"]:
        errors.append("const")
    if "enum" in schema and value not in schema["enum"]:
        errors.append("enum")
    if "type" in schema and not _matches_type(schema["type"], value):
        return errors + ["type"]
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append("minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append("maxLength")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            errors.append("pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value):
            errors.append("minimum")
        if value > schema.get("maximum", value):
            errors.append("maximum")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        errors.extend("required" for key in schema.get("required", []) if key not in value)
        if schema.get("additionalProperties") is False:
            errors.extend("additionalProperties" for key in value if key not in properties)
        for key, child in properties.items():
            if key in value:
                errors.extend(_errors(child, value[key], root))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append("minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append("maxItems")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            errors.append("uniqueItems")
        prefix_items = schema.get("prefixItems", [])
        for index, item in enumerate(value):
            item_schema = prefix_items[index] if index < len(prefix_items) else schema.get("items", {})
            if isinstance(item_schema, dict):
                errors.extend(_errors(item_schema, item, root))
            elif item_schema is False:
                errors.append("items")
    for branch in schema.get("allOf", []):
        errors.extend(_errors(branch, value, root))
    if "if" in schema and not _errors(schema["if"], value, root):
        errors.extend(_errors(schema.get("then", {}), value, root))
    return errors


def _receipt_errors(value: dict) -> list[str]:
    expected = DOCUMENTS_BY_PROFILE.get((value.get("purpose"), value.get("profile")))
    documents = value.get("documents")
    if expected is None or not isinstance(documents, list):
        return ["unknown purpose profile"]
    paths = tuple(item.get("path") for item in documents if isinstance(item, dict))
    if paths != expected:
        return ["documents must match sorted purpose profile"]
    issued_at = value.get("issued_at")
    try:
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return ["issued_at must be a real UTC instant"]
    return []


def _rotation_errors(value: dict) -> list[str]:
    if value.get("new_epoch") != value.get("old_epoch", -2) + 1:
        return ["epoch must advance once"]
    return [] if value.get("new_key_id") != value.get("old_key_id") else ["key IDs must differ"]


def validate_fixture(name: str) -> bool:
    vectors = {
        "padded-base64": ("trust-config", "public_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        "unsafe-path": ("receipt", "path", "docs/../secret.md"),
        "hostname": ("receipt", "hostname", "signer.local"),
    }
    schema_name, field, replacement = vectors[name]
    value = deepcopy(load_fixture(schema_name))
    target = value["documents"][0] if field == "path" else value
    target[field] = replacement
    return not (_errors(_schema(schema_name), value) or _receipt_errors(value))


class ProjectOwnerAuthoritySchemaTests(unittest.TestCase):
    def test_valid_redacted_fixtures_conform_to_closed_contracts(self) -> None:
        expected_ids = {
            "trust-config": "gocode.project-owner.trust-config/1",
            "receipt": "gocode.project-owner.authority-receipt/1",
            "rotation": "gocode.project-owner.key-rotation/1",
            "backup-metadata": "gocode.project-owner.encrypted-key-backup/1",
        }
        for name, schema_id in expected_ids.items():
            with self.subTest(name=name):
                schema = _schema(name)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["$id"], schema_id)
                self.assertFalse(_schema_errors(schema))
                self.assertFalse(_errors(schema, load_fixture(name)))
        self.assertFalse(_receipt_errors(load_fixture("receipt")))
        self.assertFalse(_rotation_errors(load_fixture("rotation")))
        self.assertFalse(trust_config_errors(load_fixture("trust-config")))

    def test_named_invalid_vectors_fail_closed(self) -> None:
        for name in ("padded-base64", "unsafe-path", "hostname"):
            with self.subTest(name=name):
                self.assertFalse(validate_fixture(name))

    def test_receipt_rejects_document_mutations_and_privacy_fields(self) -> None:
        schema = _schema("receipt")
        valid = load_fixture("receipt")
        vectors = []
        for field, value in (("blob_oid", "A" * 40), ("mode", "100755"), ("content_sha256", "A" * 64), ("byte_length", -1)):
            changed = deepcopy(valid)
            changed["documents"][0][field] = value
            vectors.append(changed)
        missing = deepcopy(valid)
        missing["documents"] = missing["documents"][:-1]
        vectors.append(missing)
        unsorted = deepcopy(valid)
        unsorted["documents"].reverse()
        vectors.append(unsorted)
        duplicate = deepcopy(valid)
        duplicate["documents"].append(deepcopy(duplicate["documents"][0]))
        vectors.append(duplicate)
        private = deepcopy(valid)
        private["email"] = "owner@example.test"
        vectors.append(private)
        wrong_oid_length = deepcopy(valid)
        wrong_oid_length["subject"]["object_format"] = "sha256"
        wrong_oid_length["subject"]["commit_oid"] = "3" * 64
        wrong_oid_length["subject"]["tree_oid"] = "4" * 64
        vectors.append(wrong_oid_length)
        for value in vectors:
            with self.subTest(value=value):
                self.assertTrue(_errors(schema, value) or _receipt_errors(value))

    def test_receipt_rejects_dot_path_components(self) -> None:
        schema = _schema("receipt")
        for path in (".", "..", "docs/.", "docs/.."):
            with self.subTest(path=path):
                value = deepcopy(load_fixture("receipt"))
                value["documents"][0]["path"] = path
                self.assertTrue(_errors(schema, value))

    def test_receipt_rejects_nonmatching_document_oid_format(self) -> None:
        schema = _schema("receipt")
        for object_format, oid_length in (("sha1", 64), ("sha256", 40)):
            with self.subTest(object_format=object_format):
                value = deepcopy(load_fixture("receipt"))
                value["subject"] = {"object_format": object_format, "commit_oid": "a" * oid_length, "tree_oid": "b" * oid_length}
                value["documents"][0]["blob_oid"] = "c" * (104 - oid_length)
                value["documents"][1]["blob_oid"] = "d" * oid_length
                self.assertTrue(_errors(schema, value))

    def test_receipt_requires_the_closed_purpose_profile_and_document_set(self) -> None:
        schema = _schema("receipt")
        for field, replacement in (("purpose", "OTHER_AUTHORIZATION"), ("profile", "gocode.project-owner.other/1")):
            with self.subTest(field=field):
                value = deepcopy(load_fixture("receipt"))
                value[field] = replacement
                self.assertTrue(_errors(schema, value) or _receipt_errors(value))
        value = deepcopy(load_fixture("receipt"))
        value["documents"][1]["path"] = "docs/decisions/other.json"
        self.assertTrue(_errors(schema, value))

    def test_receipt_schema_requires_exact_document_schema_bindings(self) -> None:
        schema = _schema("receipt")
        decision = deepcopy(load_fixture("receipt"))
        decision["documents"][1].pop("schema_id")
        self.assertTrue(_errors(schema, decision))
        wrong_decision = deepcopy(load_fixture("receipt"))
        wrong_decision["documents"][1]["schema_id"] = "gocode.other/1"
        self.assertTrue(_errors(schema, wrong_decision))

    def test_receipt_rejects_impossible_utc_instants(self) -> None:
        for issued_at in ("2026-99-99T99:99:99Z", "0000-00-00T00:00:00Z", "2025-02-29T00:00:00Z"):
            with self.subTest(issued_at=issued_at):
                value = deepcopy(load_fixture("receipt"))
                value["issued_at"] = issued_at
                self.assertTrue(_receipt_errors(value))
        value = deepcopy(load_fixture("receipt"))
        value["issued_at"] = "2024-02-29T00:00:00Z"
        self.assertFalse(_receipt_errors(value))

    def test_base64url_rejects_impossible_unpadded_length(self) -> None:
        backup = load_fixture("backup-metadata")
        backup["ciphertext"] = "A"
        self.assertTrue(_errors(_schema("backup-metadata"), backup))

    def test_validator_handles_type_unions_and_null_predecessors(self) -> None:
        union = {"type": ["string", "null"], "minLength": 1}
        self.assertFalse(_errors(union, None))
        self.assertTrue(_errors(union, ""))
        self.assertTrue(_errors(union, 1))
        trust = load_fixture("trust-config")
        trust["predecessor"] = "prior"
        self.assertTrue(_errors(_schema("trust-config"), trust))

    def test_schema_preflight_rejects_missing_optional_local_reference(self) -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "test/1", "title": "test", "description": "test", "type": "object",
            "properties": {"optional": {"$ref": "#/$defs/missing"}},
        }
        self.assertTrue(_schema_errors(schema))

    def test_trust_rotation_and_backup_reject_boundary_mutations(self) -> None:
        trust = load_fixture("trust-config")
        trust["unexpected"] = True
        self.assertTrue(_errors(_schema("trust-config"), trust))
        rotation = load_fixture("rotation")
        rotation["new_epoch"] += 2
        self.assertTrue(_rotation_errors(rotation))
        rotation = load_fixture("rotation")
        rotation["new_key_id"] = rotation["old_key_id"]
        self.assertTrue(_rotation_errors(rotation))
        backup = load_fixture("backup-metadata")
        backup["nonce"] = "A" * 31
        self.assertTrue(_errors(_schema("backup-metadata"), backup))
