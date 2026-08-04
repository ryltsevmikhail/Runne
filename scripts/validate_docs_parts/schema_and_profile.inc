#!/usr/bin/env python3
"""Documentation schema and immutable profile validation phase."""
import hashlib
import json
import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM_DIR = os.path.join(BASE, "upstream", "opencode")
DOCS_DIR = os.path.join(BASE, "docs")
IMPLEMENTATION_PLANS_DIR = os.path.join(DOCS_DIR, "superpowers", "plans")
BASELINE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
IGNORED_TREE_NAMES = {".git", ".worktrees", "node_modules", "target"}
EXCLUDED_ROOTS = {
    os.path.join(DOCS_DIR, "desktop"),
    os.path.join(BASE, "upstream", "desktop"),
}
HISTORIC_SCHEMA_EXCEPTIONS = {"opencode-baseline-inventory-v1.schema.json"}

errors = []
warnings = []
strict = "--strict" in sys.argv


def err(message):
    errors.append(message)


def warn(message):
    warnings.append(message)


def walk_files(root, suffixes=None):
    """Yield repository files while excluding generated and pinned source trees."""
    for current_root, directories, files in os.walk(root):
        directories[:] = [
            directory
            for directory in directories
            if directory not in IGNORED_TREE_NAMES
            and os.path.join(current_root, directory) != UPSTREAM_DIR
            and os.path.join(current_root, directory) not in EXCLUDED_ROOTS
        ]
        for filename in files:
            if suffixes is None or filename.endswith(suffixes):
                yield os.path.join(current_root, filename)


def is_implementation_plan(path):
    return path.startswith(IMPLEMENTATION_PLANS_DIR + os.sep)


def validate_const_instance(instance, schema, location):
    """Validate the closed const-only subset used by immutable profiles."""
    if "const" in schema and instance != schema["const"]:
        err(f"{location}: value differs from schema const")
        return
    expected_type = schema.get("type")
    if expected_type == "null" and instance is not None:
        err(f"{location}: expected null")
        return
    if expected_type == "object":
        if not isinstance(instance, dict):
            err(f"{location}: expected object")
            return
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = sorted(set(required) - set(instance))
        if missing:
            err(f"{location}: missing required fields {missing}")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(instance) - set(properties))
            if unknown:
                err(f"{location}: unknown fields {unknown}")
        for key in sorted(set(instance) & set(properties)):
            validate_const_instance(instance[key], properties[key], f"{location}.{key}")


schemas_dir = os.path.join(BASE, "docs", "schemas")
for filename in sorted(os.listdir(schemas_dir)):
    if not filename.endswith(".json"):
        continue
    path = os.path.join(schemas_dir, filename)
    try:
        with open(path, encoding="utf-8") as schema_file:
            data = json.load(schema_file)
    except json.JSONDecodeError as error:
        err(f"Invalid JSON: {filename} — {error}")
        continue
    if data.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        err(f"Wrong $schema in {filename}: {data.get('$schema')}")
    if not data.get("$id") and filename not in HISTORIC_SCHEMA_EXCEPTIONS:
        warn(f"Missing $id in {filename}")
    if not data.get("title"):
        warn(f"Missing title in {filename}")
    if data.get("type") != "object":
        err(f"Top-level schema must be object: {filename}")
    properties = data.get("properties")
    required = data.get("required")
    if not isinstance(properties, dict) or not properties:
        err(f"Missing/non-object properties in {filename}")
    if not isinstance(required, list) or not required:
        err(f"Missing/non-array required in {filename}")
    elif isinstance(properties, dict):
        unknown_required = sorted(set(required) - set(properties))
        if unknown_required:
            err(f"Required fields absent from properties in {filename}: {unknown_required}")
    if data.get("additionalProperties") is not False and filename not in HISTORIC_SCHEMA_EXCEPTIONS:
        err(f"Top-level schema must be closed (additionalProperties=false): {filename}")
    if "preliminary" in json.dumps(data).lower():
        err(f"Preliminary schema cannot be implementation input: {filename}")


openai_profile_path = os.path.join(DOCS_DIR, "profiles", "openai-responses-text-v1.json")
openai_digest_path = os.path.join(DOCS_DIR, "profiles", "openai-responses-text-v1.digest")
openai_schema_path = os.path.join(schemas_dir, "openai-responses-text-profile-v1.schema.json")
openai_golden_path = os.path.join(DOCS_DIR, "golden", "openai-responses-text-request-v1.json")
openai_paths = (openai_profile_path, openai_digest_path, openai_schema_path, openai_golden_path)
if all(os.path.isfile(path) for path in openai_paths):
    try:
        profile_bytes = open(openai_profile_path, "rb").read()
        profile = json.loads(profile_bytes)
        profile_schema = json.loads(open(openai_schema_path, encoding="utf-8").read())
        golden_bytes = open(openai_golden_path, "rb").read()
        golden = json.loads(golden_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        err(f"OpenAI immutable profile artifacts are unreadable: {error}")
    else:
        expected_digest = "sha256:" + hashlib.sha256(profile_bytes).hexdigest()
        actual_digest = open(openai_digest_path, encoding="utf-8").read().strip()
        if actual_digest != expected_digest:
            err("OpenAI profile digest sidecar mismatch")
        canonical_profile = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if profile_bytes != canonical_profile:
            err("OpenAI profile bytes are not exact compact UTF-8 JSON plus LF")
        validate_const_instance(profile, profile_schema, "openai-profile")
        canonical_golden = json.dumps(golden, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if golden_bytes != canonical_golden:
            err("OpenAI request golden is not exact compact UTF-8 JSON plus LF")
        expected_golden_keys = {
            "model", "service_tier", "input", "max_output_tokens", "reasoning", "tools",
            "tool_choice", "background", "store", "stream",
        }
        if (
            not isinstance(golden, dict)
            or set(golden) != expected_golden_keys
            or golden.get("model") != profile.get("model", {}).get("request_id")
            or golden.get("service_tier") != profile.get("request", {}).get("service_tier")
            or not isinstance(golden.get("input"), list)
            or not golden.get("input")
            or golden.get("reasoning") != {"effort": "none"}
            or golden.get("tools") != []
            or golden.get("tool_choice") != "none"
            or golden.get("background") is not False
            or golden.get("store") is not False
            or golden.get("stream") is not True
        ):
            err("OpenAI request golden differs from the exact text-only profile")
        for forbidden in (b"authorization", b"bearer", b"credential", b"api_key", b"secret_ref"):
            if forbidden in golden_bytes.lower():
                err(f"OpenAI request golden contains forbidden marker {forbidden!r}")
else:
    missing = [os.path.relpath(path, BASE) for path in openai_paths if not os.path.isfile(path)]
    err(f"Missing immutable OpenAI profile artifacts: {missing}")
