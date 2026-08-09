"""Closed semantic rules for non-authoritative RC0 fixture records."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Mapping

from .schemas import SCHEMA_FILES

SUPPORTED_STAGES = ("SOURCE_CANDIDATE", "PRODUCTION_QUALIFICATION")
UNSUPPORTED_STAGES = ("RELEASE_APPROVAL", "PUBLICATION_AUTHORIZATION")
BINDING_FIELDS = (
    "repository_id",
    "candidate_source_sha",
    "evidence_attempt_id",
    "observed_evidence_revision",
    "evidence_bundle_digest",
    "policy_revision",
    "policy_digest",
    "profile",
    "exact_artifact_bindings",
)
PINNED_OPENCODE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
BLOCKED_REASONS = {
    "REQUIRED_GATE_FAILED",
    "REQUIRED_GATE_NOT_RUN",
    "REQUIRED_GATE_MISMATCH",
    "REQUIRED_GATE_EVIDENCE_UNAVAILABLE",
    "REQUIRED_GATE_POLICY_UNAVAILABLE",
    "REQUIRED_GATE_AUTHORITY_UNAVAILABLE",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CHECKSUM = re.compile(r"(?P<sha>[0-9a-f]{64}) (?P<size>0|[1-9][0-9]*) (?P<path>.+)")
_CAS = re.compile(r"cas:sha256:[0-9a-f]{64}")
_GIT = re.compile(r"git:(?P<revision>[0-9a-f]{40}):(?P<path>.+)")
_WINDOWS_RESERVED = re.compile(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?")


def validate_portable_relative_path(value: Any) -> tuple[str, ...]:
    errors: list[str] = []
    if type(value) is not str or not value:
        return ("path must be a non-empty string",)
    if unicodedata.normalize("NFC", value) != value:
        errors.append("path must be NFC")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return ("path contains invalid Unicode",)
    if len(encoded) > 4096:
        errors.append("path exceeds 4096 UTF-8 bytes")
    if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value):
        errors.append("path must be relative without a root or drive")
    if "\\" in value or "//" in value:
        errors.append("path contains a backslash or repeated separator")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        errors.append("path contains a control character")
    if any(char in '<>:"|?*' for char in value):
        errors.append("path contains a non-portable character")
    segments = value.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        errors.append("path contains an empty, dot or dotdot segment")
    if any(segment.endswith((".", " ")) or _WINDOWS_RESERVED.fullmatch(segment) for segment in segments):
        errors.append("path contains a non-portable segment")
    return tuple(errors)


def validate_content_locator(value: Any) -> tuple[str, ...]:
    if type(value) is not str:
        return ("locator must be a string",)
    if _CAS.fullmatch(value):
        return ()
    match = _GIT.fullmatch(value)
    if match and not validate_portable_relative_path(match["path"]):
        return ()
    return ("locator must pin a lower-case content digest or Git revision",)


def parse_checksums_text(raw: bytes, error_type: type[ValueError] = ValueError) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > 65_536:
        raise error_type("checksums input must be bounded bytes")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\t" in raw or raw.startswith(b"\xef\xbb\xbf"):
        raise error_type("checksums requires BOM-free LF-only text")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise error_type("checksums is not strict UTF-8") from error
    lines = text[:-1].split("\n")
    names = ("repository_id", "candidate_source_revision", "evidence_attempt_id", "policy_digest")
    if len(lines) < 5 or any(not line for line in lines):
        raise error_type("checksums requires four headers and artifacts")
    identity: dict[str, str] = {}
    for name, line in zip(names, lines[:4], strict=True):
        prefix = name + "="
        if not line.startswith(prefix) or not line[len(prefix) :]:
            raise error_type(f"invalid checksums header: {name}")
        identity[name] = line[len(prefix) :]
    if re.fullmatch(r"[0-9a-f]{40}", identity["candidate_source_revision"]) is None:
        raise error_type("invalid candidate source revision")
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", identity["evidence_attempt_id"]) is None:
        raise error_type("invalid evidence attempt UUIDv7")
    if _SHA256.fullmatch(identity["policy_digest"]) is None:
        raise error_type("invalid policy digest")
    artifacts: list[dict[str, Any]] = []
    for line in lines[4:]:
        match = _CHECKSUM.fullmatch(line)
        if match is None or validate_portable_relative_path(match["path"]):
            raise error_type("invalid canonical artifact checksum line")
        size = int(match["size"])
        if size > 2**64 - 1:
            raise error_type("artifact size exceeds u64")
        artifacts.append({"relative_path": match["path"], "sha256": match["sha"], "size": size})
    paths = [item["relative_path"] for item in artifacts]
    keys = [(item["relative_path"], item["sha256"]) for item in artifacts]
    if paths != sorted(paths, key=lambda value: value.encode("utf-8")):
        raise error_type("artifact lines are not UTF-8-path sorted")
    if len(set(paths)) != len(paths) or len(set(keys)) != len(keys):
        raise error_type("duplicate artifact checksum entry")
    return {"schema_id": "gocode.rc0.schema.checksums-text/3", **identity, "artifacts": artifacts}


def _artifact_keys(records: Any, label: str) -> tuple[set[tuple[str, str]], list[str]]:
    if not isinstance(records, list):
        return set(), [f"{label}: artifacts must be an array"]
    keys: set[tuple[str, str]] = set()
    errors: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            errors.append(f"{label}: artifact must be an object")
            continue
        path, digest = record.get("relative_path"), record.get("sha256")
        errors.extend(f"{label}: {item}" for item in validate_portable_relative_path(path))
        if type(path) is not str or type(digest) is not str or _SHA256.fullmatch(digest) is None:
            errors.append(f"{label}: malformed artifact digest")
            continue
        key = (path, digest)
        if key in keys:
            errors.append(f"{label}: duplicate artifact key {key!r}")
        keys.add(key)
    return keys, errors


def validate_artifact_bijection(inventory: Mapping[str, Any], checksums: Mapping[str, Any], spdx: Mapping[str, Any]) -> tuple[str, ...]:
    sources = (("artifact-inventory", inventory.get("artifacts")), ("checksums", checksums.get("artifacts")), ("SPDX", spdx.get("artifact_bindings")))
    sets: list[set[tuple[str, str]]] = []
    errors: list[str] = []
    for label, records in sources:
        keys, found = _artifact_keys(records, label)
        sets.append(keys)
        errors.extend(found)
    if not errors and not (sets[0] == sets[1] == sets[2]):
        errors.append("artifact-inventory, checksums and SPDX keys are not an exact bijection")
    if errors:
        return tuple(errors)
    inventory_by_key = {(item["relative_path"], item["sha256"]): item for item in inventory["artifacts"]}
    checksums_by_key = {(item["relative_path"], item["sha256"]): item for item in checksums["artifacts"]}
    if any(inventory_by_key[key].get("size") != checksums_by_key[key].get("size") for key in inventory_by_key):
        errors.append("artifact inventory and checksums size binding mismatch")
    locators = [item.get("locator") for item in inventory["artifacts"]]
    for item, locator in zip(inventory["artifacts"], locators, strict=True):
        errors.extend(validate_content_locator(locator))
        if isinstance(locator, str) and locator.startswith("cas:sha256:") and locator.removeprefix("cas:sha256:") != item.get("sha256"):
            errors.append("content-addressed locator digest does not bind artifact sha256")
        if isinstance(locator, str) and locator.startswith("git:") and locator.split(":", 2)[1] != inventory.get("candidate_source_revision"):
            errors.append("Git locator revision does not bind candidate source")
    if _duplicates(locators):
        errors.append("artifact locator is not unique")
    return tuple(errors)


def validate_artifact_inventory(inventory: Mapping[str, Any]) -> tuple[str, ...]:
    artifacts = inventory.get("artifacts")
    if not isinstance(artifacts, list) or any(not isinstance(item, dict) for item in artifacts):
        return ("artifact inventory must contain an artifact object array",)
    checksums = {
        "artifacts": [
            {"relative_path": item.get("relative_path"), "sha256": item.get("sha256"), "size": item.get("size")}
            for item in artifacts
        ]
    }
    spdx = {
        "artifact_bindings": [
            {"relative_path": item.get("relative_path"), "sha256": item.get("sha256")}
            for item in artifacts
        ]
    }
    return validate_artifact_bijection(inventory, checksums, spdx)


def validate_source_capture(capture: Mapping[str, Any], source_sha: Any) -> tuple[str, ...]:
    if not isinstance(capture, Mapping):
        return ("source capture must be an object",)
    errors: list[str] = []
    for field in ("head_revision", "captured_origin_main_revision"):
        if capture.get(field) != source_sha:
            errors.append(f"source capture {field} does not bind candidate source")
    pairs = (
        ("raw_tree_oid", "current_tree_oid", 40, None),
        ("raw_gitmodules_sha256", "current_gitmodules_sha256", 64, None),
        ("raw_opencode_gitlink_revision", "current_opencode_gitlink_revision", 40, PINNED_OPENCODE_SHA),
    )
    for left, right, length, pinned in pairs:
        for field in (left, right):
            value = capture.get(field)
            if type(value) is not str or len(value) != length or any(char not in "0123456789abcdef" for char in value):
                errors.append(f"source capture {field} is not exact lower-case hex")
        if capture.get(left) != capture.get(right):
            errors.append(f"source capture {left}/{right} mismatch")
        if pinned and capture.get(left) != pinned:
            errors.append(f"source capture {left} is not the pinned OpenCode SHA")
    if capture.get("capture_evidence_kind") != "RAW_GIT_OBJECTS":
        errors.append("source capture is not independently bound to raw Git objects")
    return tuple(errors)


def _duplicates(values: Any) -> bool:
    if not isinstance(values, list):
        return True
    return any(value in values[:index] for index, value in enumerate(values))


def validate_policy_inventory(policy: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    schemas = policy.get("expected_schema_digests", [])
    if not isinstance(schemas, list):
        schemas = []
        errors.append("policy schema inventory must be an array")
    schema_ids = [item.get("schema_id") for item in schemas if isinstance(item, dict)]
    if any(type(value) is not str for value in schema_ids) or len(schema_ids) != len(SCHEMA_FILES) or set(schema_ids) != set(SCHEMA_FILES) or _duplicates(schema_ids):
        errors.append("policy schema inventory must contain each exact committed schema ID once")
    gates = policy.get("required_gates", [])
    if not isinstance(gates, list):
        gates = []
        errors.append("policy required gate inventory must be an array")
    gate_ids = [gate.get("gate_id") for gate in gates if isinstance(gate, dict)]
    if not gate_ids or any(type(value) is not str for value in gate_ids) or _duplicates(gate_ids):
        errors.append("policy required gate_id values must be non-empty and unique")
    stages = [gate.get("stage") for gate in gates if isinstance(gate, dict)]
    if any(type(value) is not str for value in stages) or set(stages) != set(SUPPORTED_STAGES):
        errors.append("policy must cover the exact supported required stage set")
    selectors: list[str] = []
    for gate in gates:
        if not isinstance(gate, dict):
            errors.append("policy gate must be an object")
            continue
        if gate.get("required") is not True or gate.get("identity_profile_bindings") != list(BINDING_FIELDS):
            errors.append(f"policy gate {gate.get('gate_id')!r} has incomplete exact bindings")
        current = gate.get("selectors", [])
        if not isinstance(current, list) or not current or _duplicates(current) or any(type(value) is not str or value == "UNRESOLVED" for value in current):
            errors.append(f"policy gate {gate.get('gate_id')!r} selectors are not closed and unique")
        if isinstance(current, list):
            selectors.extend(value for value in current if isinstance(value, str))
    if _duplicates(selectors):
        errors.append("policy selectors must be unique across required gates")
    for field in ("trusted_evidence_issuers", "workflow_policy_digests"):
        values = policy.get(field, [])
        if _duplicates(values):
            errors.append(f"policy {field} contains duplicate keys")
    return tuple(errors)
