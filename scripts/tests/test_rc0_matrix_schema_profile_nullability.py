"""Matrix `/2` profile digest shape and Task 7 semantic-boundary tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.rc0_policy.adjunct_schema_validation import (
    parse_adjunct_schema,
    validate_adjunct_schema_instance,
)


_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_ID = "gocode.release.platform-qualification-matrix/2"
_SHA = "a" * 64


def _profile(state: str, digest: object) -> dict[str, object]:
    return {
        "profile_id": "gocode-openai-responses-text/1",
        "profile_revision": 1,
        "profile_sha256": digest,
        "state": state,
        "evidence_envelope_sha256": _SHA,
    }


def _schema() -> dict[str, object]:
    path = _ROOT / "docs/schemas/release-platform-qualification-matrix-v2.schema.json"
    return parse_adjunct_schema(path.read_bytes(), _SCHEMA_ID)


def _matrix(profile: dict[str, object]) -> dict[str, object]:
    scopes = (
        ("linux-ubuntu-24_04-x86_64-production", "production", "supported", "Ubuntu", "24.04", "linux-build", "x86_64"),
        ("windows-11-24h2-x86_64-production", "production", "supported", "Windows", "11 24H2", "windows-build", "x86_64"),
        ("macos-14-arm64-development-preview", "development_preview", "unsupported", "macOS", "14", "macos-build", "arm64"),
    )
    cells = []
    for index, (scope, qualification, disposition, family, version, build, architecture) in enumerate(scopes):
        row = profile if index == 0 else _profile("required", _SHA)
        cells.append({
            "platform_scope_id": scope, "qualification_class": qualification,
            "support_disposition": disposition, "os_family": family,
            "os_version": version, "os_build": build,
            "kernel_or_image_sha256": _SHA, "architecture": architecture,
            "native_mode": "native", "profile_rows": [row],
            "artifact_rows": [{"artifact_slot_id": f"slot-{index}", "relative_path": f"artifact-{index}", "sha256": _SHA, "size": 0, "locator": f"cas:sha256:{_SHA}", "artifact_manifest_payload_sha256": _SHA, "product_manifest_payload_sha256": _SHA}],
            "evidence_envelope_sha256s": [_SHA],
        })
    return {
        "schema_version": _SCHEMA_ID, "repository_id": "gocode",
        "platform_qualified_subject_envelope_sha256": _SHA,
        "normalized_platform_mapping": {"schema_version": "gocode.rc0.normalized-platform-mapping/1", "repository_id": "gocode", "cells": cells},
        "normalized_platform_mapping_payload_sha256": _SHA,
    }


class MatrixSchemaProfileNullabilityTests(unittest.TestCase):
    def test_all_profile_states_accept_their_canonical_digest_shape(self) -> None:
        for state, digest in (
            ("required", _SHA),
            ("external_canary_only", _SHA),
            ("disabled_by_policy", None),
            ("backend_unavailable", None),
        ):
            with self.subTest(state=state):
                self.assertEqual(validate_adjunct_schema_instance(_schema(), _matrix(_profile(state, digest))), ())

    def test_rejects_missing_boolean_and_noncanonical_digest_for_every_state(self) -> None:
        for state in ("required", "external_canary_only", "disabled_by_policy", "backend_unavailable"):
            missing = _profile(state, _SHA)
            del missing["profile_sha256"]
            for name, value in (
                ("missing", missing),
                ("boolean", _profile(state, True)),
                ("short", _profile(state, "a" * 63)),
                ("trailing_newline", _profile(state, _SHA + "\n")),
            ):
                with self.subTest(state=state, mutation=name):
                    self.assertTrue(validate_adjunct_schema_instance(_schema(), _matrix(value)))

    def test_schema_defers_state_digest_relation_to_task_seven_semantic_verifier(self) -> None:
        # The bounded schema subset lacks if/then: Task 7 owns this relation.
        for state, digest in (
            ("required", None),
            ("external_canary_only", None),
            ("disabled_by_policy", _SHA),
            ("backend_unavailable", _SHA),
        ):
            with self.subTest(state=state):
                self.assertEqual(validate_adjunct_schema_instance(_schema(), _matrix(_profile(state, digest))), ())


if __name__ == "__main__":
    unittest.main()
