"""Structural regression tests for the immutable Desktop v1 registry."""

import hashlib
import unittest

from scripts.tests.desktop_capability_manifest_support import (
    CAPABILITY_SCHEMA,
    PROFILE,
    PROFILE_DIGEST,
    STATUS,
    STATUS_SCHEMA,
    load_json_no_duplicates,
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


if __name__ == "__main__":
    unittest.main()
