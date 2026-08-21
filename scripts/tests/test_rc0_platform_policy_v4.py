"""Profile-v4 successors through the active qualification chain."""

from __future__ import annotations

import unittest

from scripts.rc0_policy.platform_policy import PolicyFailure, fixture_verify_mapping_policy, validate_report_against_policy, verify_qualified_declaration
from scripts.tests.rc0_platform_attestation_closure_support import (
    replace_host_profile,
    replace_measurement_profile,
    valid_closure_fixture,
)
from scripts.tests.rc0_platform_policy_support import valid_declaration_fixture, valid_mapping_fixture


V3 = "gocode.rc0.evidence-profile/3"
V4 = "gocode.rc0.evidence-profile/4"


class Rc0PlatformPolicyV4Tests(unittest.TestCase):
    def test_v4_mapping_report_declaration_and_closure_chain_is_accepted(self) -> None:
        mapping_fixture = valid_mapping_fixture(profile=V4)
        mapping = fixture_verify_mapping_policy(**mapping_fixture.arguments())
        schema_ids = dict(mapping.rc0_trust_policy.schema_id_hash_pairs)
        self.assertIn("gocode.rc0.schema.verification-report/4", schema_ids)
        self.assertNotIn("gocode.rc0.schema.verification-report/3", schema_ids)

        fixture = valid_declaration_fixture(profile=V4)
        declaration = verify_qualified_declaration(
            fixture.declaration, fixture.policy, fixture.mapping,
            fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds,
        )
        self.assertEqual(declaration.report.common_binding_group_payload_sha256, declaration.common_binding_group_payload_sha256)

        closure = valid_closure_fixture("linux-appimage")
        v4_closure = closure.__class__(
            replace_measurement_profile(closure.measurement_a, V4),
            replace_measurement_profile(closure.measurement_b, V4),
            replace_host_profile(closure.host_record, V4),
        )
        from scripts.rc0_policy.artifact_closure import verify_artifact_closure

        self.assertEqual(
            verify_artifact_closure(
                v4_closure.measurement_a, v4_closure.measurement_b,
                v4_closure.host_record,
            ).artifact_slot_id,
            "linux-appimage",
        )

    def test_v4_and_v3_report_downgrades_are_rejected_in_both_directions(self) -> None:
        v3 = valid_declaration_fixture(profile=V3)
        v4 = valid_declaration_fixture(profile=V4)
        for report, mapping in (
            (v3.report, v4.mapping),
            (v4.report, v3.mapping),
        ):
            with self.subTest(profile=report.payload_schema_id):
                with self.assertRaisesRegex(PolicyFailure, "REPORT_PROJECTION_MISMATCH"):
                    validate_report_against_policy(
                        report, mapping.rc0_trust_policy, mapping,
                        v3.now_epoch_seconds,
                    )

    def test_v4_and_v3_declaration_downgrades_are_rejected(self) -> None:
        v3 = valid_declaration_fixture(profile=V3)
        v4 = valid_declaration_fixture(profile=V4)
        for fixture, mapping in ((v3, v4.mapping), (v4, v3.mapping)):
            with self.subTest(schema=fixture.declaration.payload_schema_id):
                with self.assertRaises(PolicyFailure):
                    verify_qualified_declaration(
                        fixture.declaration, fixture.policy, mapping,
                        fixture.resolver, fixture.verify_envelope,
                        fixture.now_epoch_seconds,
                    )


if __name__ == "__main__":
    unittest.main()
