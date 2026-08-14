"""Regression tests for the complete RC0 common binding projection."""

from __future__ import annotations

import hashlib
import unittest
from copy import deepcopy

from scripts.rc0_policy.canonical import canonical_bytes
from scripts.rc0_policy.platform_policy_report import _common
from scripts.rc0_policy.rules import BINDING_FIELDS


def _binding() -> dict[str, object]:
    return {
        "repository_id": "gocode",
        "candidate_source_sha": "a" * 40,
        "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
        "observed_evidence_revision": "b" * 40,
        "evidence_bundle_digest": "d" * 64,
        "policy_revision": 3,
        "policy_digest": "c" * 64,
        "profile": "gocode.rc0.evidence-profile/3",
        "exact_artifact_bindings": [{
            "relative_path": "dist/gocode.tar",
            "sha256": "f" * 64,
            "size": 3,
            "locator": "cas:sha256:" + "f" * 64,
        }],
    }


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class CompleteCommonBindingTests(unittest.TestCase):
    def test_report_projection_uses_rules_binding_fields_in_exact_order(self) -> None:
        self.assertEqual(tuple(_common(_binding())), BINDING_FIELDS)

    def test_each_previously_omitted_field_changes_common_digest(self) -> None:
        original = _common(_binding())
        for field in ("observed_evidence_revision", "evidence_bundle_digest", "policy_revision", "exact_artifact_bindings"):
            changed = deepcopy(_binding())
            if field == "policy_revision":
                changed[field] = 4
            elif field == "exact_artifact_bindings":
                changed[field][0]["locator"] = "cas:sha256:" + "e" * 64
            else:
                changed[field] = ("e" * 40 if field.endswith("revision") else "e" * 64)
            with self.subTest(field=field):
                self.assertNotEqual(_digest(original), _digest(_common(changed)))


if __name__ == "__main__":
    unittest.main()
