"""Structural and semantic regression tests for the Desktop v1 registry."""

import hashlib
import unittest

from scripts.tests.desktop_capability_manifest_support import (
    CAPABILITY_SCHEMA,
    PROFILE,
    PROFILE_DIGEST,
    STATUS,
    STATUS_SCHEMA,
    definition,
    load_json_no_duplicates,
    status,
    status_with_track_stages,
    validate_track_stages,
)


class DesktopCapabilityManifestTests(unittest.TestCase):
    def test_schema_rejects_truncated_track_stages(self) -> None:
        schema = load_json_no_duplicates(CAPABILITY_SCHEMA)
        definition = load_json_no_duplicates(PROFILE)
        stages = definition["capabilities"][0]["tracks"][0]["stages"][:-1]

        with self.assertRaisesRegex(ValueError, "minItems"):
            validate_track_stages(schema, stages)

    def test_repository_artifacts_are_closed_and_weighted(self) -> None:
        capability_schema = load_json_no_duplicates(CAPABILITY_SCHEMA)
        status_schema = load_json_no_duplicates(STATUS_SCHEMA)
        definition = load_json_no_duplicates(PROFILE)
        status = load_json_no_duplicates(STATUS)

        self.assertEqual(capability_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(capability_schema["additionalProperties"])
        self.assertTrue(capability_schema["required"])
        self.assertEqual(status_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(status_schema["additionalProperties"])
        self.assertTrue(status_schema["required"])
        self.assertEqual(definition["schema_version"], "desktop-v1-capabilities.v1")
        self.assertEqual(sum(c["weight_bps"] for c in definition["capabilities"]), 10_000)
        self.assertEqual(
            PROFILE_DIGEST.read_text(encoding="utf-8"),
            f"sha256:{hashlib.sha256(PROFILE.read_bytes()).hexdigest()}\n",
        )
        self.assertNotIn("current_stage", status)
        self.assertNotIn("score_bps", status)
        self.assertNotIn("fully_qualified", status)
        self.assertEqual(status["schema_version"], "desktop-v1-capability-status.v1")
        self.assertTrue(all(row["disposition"] == "not_recorded" for row in status["gates"]))
        self.assertTrue(all(row["disposition"] == "blocked" for row in status["capabilities"]))

    def test_definition_rejects_unknown_references_and_dependency_cycles(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_definition

        value = definition()
        value["capabilities"][0]["requirement_ids"] = ["REQ-UNKNOWN"]
        errors = validate_definition(value, {"REQ-PRD-005"}, {"SA-014"})
        self.assertIn("DEFINITION_UNKNOWN_REQUIREMENT:CAP-RTS:REQ-UNKNOWN", errors)

        value = definition()
        value["capabilities"][0]["build_requires"].append("CAP-PJW")
        errors = validate_definition(value, {item for capability in value["capabilities"] for item in capability["requirement_ids"]}, {item for capability in value["capabilities"] for item in capability["abuse_case_ids"]})
        self.assertIn("DEFINITION_DEPENDENCY_CYCLE", errors)

    def test_definition_rejects_non_contiguous_stages(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_definition

        value = definition()
        value["capabilities"][0]["tracks"][0]["stages"][2]["stage"] = 70
        errors = validate_definition(value, {item for capability in value["capabilities"] for item in capability["requirement_ids"]}, {item for capability in value["capabilities"] for item in capability["abuse_case_ids"]})
        self.assertIn("DEFINITION_NONCONTIGUOUS_STAGES:CAP-RTS:runtime-session", errors)

    def test_status_rejects_missing_platform_and_reused_artifact(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_status

        value = status()
        value["platforms"].pop()
        self.assertIn("STATUS_MISSING_PLATFORM:LINUX-UBUNTU-22-04-X86-64", validate_status(definition(), value))

        value = status_with_track_stages((40, 0, 0))
        value["gates"][1]["evidence_ref"] = value["gates"][0]["evidence_ref"]
        self.assertIn("STATUS_REUSED_EVIDENCE:GATE-CONTRACT-SCHEMA", validate_status(definition(), value))

    def test_status_rejects_compile_only_or_stub_evidence(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_status

        value = status_with_track_stages((20, 0, 0))
        value["gates"][0]["evidence_ref"] = "compile-only-stub"
        value["evidence_refs"] = [{"id": "compile-only-stub", "sha256": "1" * 64}]
        self.assertIn("STATUS_UNTRUSTED_EVIDENCE:GATE-CONTRACT-SCHEMA", validate_status(definition(), value))

    def test_evaluate_uses_lowest_track_stage_and_never_qualifies_without_binding(self) -> None:
        from scripts.desktop.capability_manifest_impl.scoring import evaluate

        definition_value = definition()
        definition_value["capabilities"] = [item for item in definition_value["capabilities"] if item["id"] == "CAP-SET"]
        evaluation = evaluate(definition_value, status_with_track_stages((100, 80, 100)))
        self.assertEqual(evaluation.capability_stages, (("CAP-SET", 80),))
        self.assertFalse(evaluation.fully_qualified)
        self.assertIn("SOURCE_BINDING_NOT_VERIFIED", evaluation.blockers)

    def test_evaluate_ignores_forged_computed_status_fields(self) -> None:
        from scripts.desktop.capability_manifest_impl.scoring import evaluate

        value = status()
        value["score_bps"] = 10_000
        value["fully_qualified"] = True
        evaluation = evaluate(definition(), value)
        self.assertEqual(evaluation.score_bps, 0)
        self.assertFalse(evaluation.fully_qualified)

    def test_repository_rejects_raw_definition_digest_mismatch(self) -> None:
        from scripts.desktop.capability_manifest_impl.io import has_raw_sha256

        self.assertFalse(has_raw_sha256(PROFILE.read_bytes(), "sha256:" + "0" * 64 + "\n"))
        self.assertEqual(PROFILE_DIGEST.read_text(encoding="utf-8").strip().split(":", 1)[1], hashlib.sha256(PROFILE.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
