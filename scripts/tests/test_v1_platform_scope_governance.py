"""Governance contract checks for the v1 platform-scope decision."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from scripts.tests.v1_platform_scope_governance_support import (
    authority_errors,
    parse_front_matter,
)

ROOT = Path(__file__).resolve().parents[2]
DECISION = ROOT / "docs/decisions/v1-platform-scope-v1.json"
SCHEMA = ROOT / "docs/schemas/v1-platform-scope-decision-v1.schema.json"
RUNTIME_ADR = ROOT / "docs/adr/ADR-0027-v1-platform-scope.md"
DESKTOP_ADR = ROOT / "docs/desktop/adr/ADR-0015-v1-platform-scope.md"

EXPECTED_PAYLOAD = {
    "artifact_slots": [
        {"artifact_slot_id": "linux-appimage", "platform_scope_id": "linux-ubuntu-24_04-x86_64-production"},
        {"artifact_slot_id": "linux-deb", "platform_scope_id": "linux-ubuntu-24_04-x86_64-production"},
        {"artifact_slot_id": "macos-app-development-adhoc", "platform_scope_id": "macos-14-arm64-development-preview"},
        {"artifact_slot_id": "macos-dmg-development-adhoc", "platform_scope_id": "macos-14-arm64-development-preview"},
        {"artifact_slot_id": "windows-installer-unsigned", "platform_scope_id": "windows-11-24h2-x86_64-production"},
    ],
    "platform_scopes": [
        {"architecture": "x86_64", "os_family": "Ubuntu", "os_version": "24.04", "platform_scope_id": "linux-ubuntu-24_04-x86_64-production", "qualification_class": "production"},
        {"architecture": "arm64", "os_family": "macOS", "os_version": "14", "platform_scope_id": "macos-14-arm64-development-preview", "qualification_class": "development_preview"},
        {"architecture": "x86_64", "os_family": "Windows", "os_version": "11-24H2-client", "platform_scope_id": "windows-11-24h2-x86_64-production", "qualification_class": "production"},
    ],
    "repository_id": "gocode",
    "schema_version": "gocode.governance.v1-platform-scope-decision/1",
    "unsupported_tuples": ["android", "ios-ipados", "macos-13", "macos-x86_64", "ubuntu-22.04", "windows-10-22h2", "windows-server"],
}


def parse_unique_json(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=reject_duplicates)


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"


def validation_errors(
    schema: object, value: object, path: str = "$", root: object | None = None
) -> list[str]:
    if not isinstance(schema, dict):
        return [f"{path}: schema must be an object"]
    root = schema if root is None else root
    reference = schema.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/$defs/"):
        definition = root["$defs"][reference.removeprefix("#/$defs/")]
        return validation_errors(definition, value, path, root)
    if "const" in schema and value != schema["const"]:
        return [f"{path}: does not match const"]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{path}: is outside enum"]

    expected_type = schema.get("type")
    if expected_type == "object" and not isinstance(value, dict):
        return [f"{path}: expected object"]
    if expected_type == "array" and not isinstance(value, list):
        return [f"{path}: expected array"]
    if expected_type == "string" and not isinstance(value, str):
        return [f"{path}: expected string"]

    errors: list[str] = []
    if isinstance(value, dict):
        required = schema.get("required", [])
        errors.extend(f"{path}: missing {key}" for key in required if key not in value)
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errors.extend(
                f"{path}: unexpected {key}" for key in value if key not in properties
            )
        for key, property_schema in properties.items():
            if key in value:
                errors.extend(validation_errors(property_schema, value[key], f"{path}.{key}", root))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: too few items")
        maximum = schema.get("maxItems")
        if maximum is not None and len(value) > maximum:
            errors.append(f"{path}: too many items")
        if schema.get("uniqueItems") is True:
            for index, item in enumerate(value):
                if any(item == prior for prior in value[:index]):
                    errors.append(f"{path}: duplicate item")
        for index, item_schema in enumerate(schema.get("prefixItems", [])):
            if index < len(value):
                errors.extend(validation_errors(item_schema, value[index], f"{path}[{index}]", root))
        if schema.get("items") is False and len(value) > len(schema.get("prefixItems", [])):
            errors.append(f"{path}: unexpected array item")
    return errors


class GovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        for path in (DECISION, SCHEMA, RUNTIME_ADR, DESKTOP_ADR):
            self.assertTrue(path.is_file(), f"missing governance artifact: {path.relative_to(ROOT)}")

    def test_both_adrs_bind_one_recomputed_payload_digest(self) -> None:
        raw = DECISION.read_bytes()
        payload = parse_unique_json(raw)
        self.assertEqual(raw, canonical_json_bytes(payload))
        digest = hashlib.sha256(raw).hexdigest()
        schema_digest = hashlib.sha256(SCHEMA.read_bytes()).hexdigest()
        self.assert_adr(RUNTIME_ADR, digest, schema_digest, "gocode-runtime", "runtime")
        self.assert_adr(DESKTOP_ADR, digest, schema_digest, "gocode-desktop", "desktop")

    def test_owner_domains_are_independent(self) -> None:
        runtime_front_matter = parse_front_matter(RUNTIME_ADR.read_text(encoding="utf-8"))
        desktop_front_matter = parse_front_matter(DESKTOP_ADR.read_text(encoding="utf-8"))
        self.assertEqual(runtime_front_matter["owners"], ["gocode-runtime"])
        self.assertEqual(desktop_front_matter["owners"], ["gocode-desktop"])
        self.assertNotEqual(runtime_front_matter["owners"], desktop_front_matter["owners"])

    def test_schema_rejects_noncanonical_platform_decisions(self) -> None:
        payload = parse_unique_json(DECISION.read_bytes())
        self.assertEqual(payload, EXPECTED_PAYLOAD)
        schema = parse_unique_json(SCHEMA.read_bytes())
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(validation_errors(schema, payload))

        duplicate_scope = json.loads(json.dumps(payload))
        duplicate_scope["platform_scopes"][1] = duplicate_scope["platform_scopes"][0]
        self.assertTrue(validation_errors(schema, duplicate_scope))

        reordered_slots = json.loads(json.dumps(payload))
        reordered_slots["artifact_slots"][0], reordered_slots["artifact_slots"][1] = (
            reordered_slots["artifact_slots"][1],
            reordered_slots["artifact_slots"][0],
        )
        self.assertTrue(validation_errors(schema, reordered_slots))

        missing_slot = json.loads(json.dumps(payload))
        missing_slot["artifact_slots"] = missing_slot["artifact_slots"][:-1]
        self.assertTrue(validation_errors(schema, missing_slot))

        extra_property = json.loads(json.dumps(payload))
        extra_property["platform_scopes"][0]["unexpected"] = True
        self.assertTrue(validation_errors(schema, extra_property))

    def assert_adr(
        self,
        path: Path,
        payload_digest: str,
        schema_digest: str,
        document_owner: str,
        protocol_owner_domain: str,
    ) -> None:
        content = path.read_text(encoding="utf-8")
        front_matter = parse_front_matter(content)
        self.assertEqual(front_matter["owners"], [document_owner])
        self.assertEqual(front_matter["status"], "ready")
        self.assertIn(f"`shared_decision_payload_sha256`: `{payload_digest}`", content)
        self.assertIn(f"`shared_decision_schema_sha256`: `{schema_digest}`", content)
        self.assertFalse(authority_errors(content, front_matter, protocol_owner_domain))


class AuthorityMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.content = RUNTIME_ADR.read_text(encoding="utf-8")

    def errors(self, content: str, domain: str = "runtime") -> list[str]:
        return authority_errors(content, parse_front_matter(content), domain)

    def accepted_content(self, content: str, visible_status: str) -> str:
        accepted_status = visible_status.replace("proposed", "accepted").replace(
            "Proposed", "Accepted"
        )
        return content.replace(visible_status, accepted_status, 1).replace(
            "`owner_acceptance_state`: `pending`", "`owner_acceptance_state`: `accepted`", 1
        ).replace(
            "`owner_acceptance_record`: `not_recorded`", "`owner_acceptance_record`: `recorded`", 1
        )

    def test_authority_status_is_only_in_exact_fields(self) -> None:
        for path, domain in ((RUNTIME_ADR, "runtime"), (DESKTOP_ADR, "desktop")):
            content = path.read_text(encoding="utf-8")
            self.assertFalse(self.errors(content, domain))
            narrative = content
            for value in ("status: ready", "**Status:** proposed", "Proposed.", "`owner_acceptance_state`: `pending`", "`owner_acceptance_record`: `not_recorded`"):
                narrative = narrative.replace(value, "")
            for term in ("proposed", "proposal", "предлагает", "не зафиксировано", "статус остаётся"):
                self.assertNotIn(term, narrative.lower())
            for illegal_status in ("proposed", "accepted"):
                with self.subTest(path=path, illegal_status=illegal_status):
                    mutated = content.replace("status: ready", f"status: {illegal_status}", 1)
                    self.assertIn(
                        "front matter status must be ready", self.errors(mutated, domain)
                    )

    def test_duplicate_authority_field_is_rejected(self) -> None:
        duplicate = self.content.replace(
            "`owner_domain`: `runtime`.",
            "`owner_domain`: `runtime`.\n\n`owner_domain`: `runtime`.",
            1,
        )
        self.assertIn("owner_domain is missing, duplicate, or contradictory", self.errors(duplicate))

    def test_accepted_transition_rejects_stale_state_and_record(self) -> None:
        stale = self.accepted_content(self.content, "**Status:** proposed").replace(
            "`owner_acceptance_state`: `accepted`", "`owner_acceptance_state`: `pending`", 1
        ).replace(
            "`owner_acceptance_record`: `recorded`", "`owner_acceptance_record`: `not_recorded`", 1
        )
        errors = self.errors(stale)
        self.assertIn("owner_acceptance_state is missing, duplicate, or contradictory", errors)
        self.assertIn("owner_acceptance_record is missing, duplicate, or contradictory", errors)

    def test_inline_issuer_and_subject_are_rejected(self) -> None:
        for field in ("issuer", "owner_subject_id"):
            with self.subTest(field=field):
                self.assertIn("ADR must not contain inline authority material", self.errors(self.content + f"\n`{field}`: `invented`.\n"))

    def test_coherent_accepted_transition_is_allowed(self) -> None:
        for path, domain, visible in ((RUNTIME_ADR, "runtime", "**Status:** proposed"), (DESKTOP_ADR, "desktop", "Proposed.")):
            content = path.read_text(encoding="utf-8")
            self.assertFalse(self.errors(content, domain))
            transitioned = self.accepted_content(content, visible)
            self.assertEqual(parse_front_matter(transitioned)["status"], "ready")
            self.assertFalse(self.errors(transitioned, domain))


if __name__ == "__main__":
    unittest.main()
