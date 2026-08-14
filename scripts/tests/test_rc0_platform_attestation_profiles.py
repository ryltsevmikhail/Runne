"""Profile and canary semantics for fixture-only platform attestations."""

from __future__ import annotations

import unittest

from scripts.rc0_policy.platform_attestation_profiles import (
    AttestationFailure,
    verify_host_policy,
    verify_profile_rows,
)
from scripts.tests.rc0_platform_attestation_profiles_support import valid_profile_fixture
from scripts.tests.rc0_platform_attestation_windows_support import windows_binding, windows_controls


class ProfileSemanticsTests(unittest.TestCase):
    def test_profile_sha_nullability_and_canonical_result_follow_mapping_state(self) -> None:
        scope = "windows-11-24h2-x86_64-production"
        fixture = valid_profile_fixture(scope)
        rows = verify_profile_rows(fixture.profiles, fixture.canaries, fixture.mapping, fixture.report, scope)
        self.assertEqual({row.state for row in rows}, {"required", "disabled_by_policy", "backend_unavailable"})
        self.assertTrue(all(row.profile_sha256 is not None for row in rows if row.state == "required"))
        self.assertTrue(all(row.profile_sha256 is None for row in rows if row.state != "required"))

    def test_macos_external_canary_is_present_and_bound(self) -> None:
        scope = "macos-14-arm64-development-preview"
        fixture = valid_profile_fixture(scope)
        rows = verify_profile_rows(fixture.profiles, fixture.canaries, fixture.mapping, fixture.report, scope)
        self.assertEqual(len(fixture.canaries), 1)
        self.assertEqual(next(row for row in rows if row.state == "external_canary_only").canonical_result, "PASS")
        with self.assertRaisesRegex(AttestationFailure, "PROFILE_MISMATCH"):
            verify_profile_rows(fixture.profiles, (), fixture.mapping, fixture.report, scope)

    def test_requires_exact_mapping_host_pins(self) -> None:
        scope = "windows-11-24h2-x86_64-production"
        fixture = valid_profile_fixture(scope)
        platform = next(row for row in fixture.mapping.platform_scopes if row.platform_scope_id == scope)
        pin = next(row for row in fixture.mapping.host_identity_pins if row.platform_scope_id == scope)
        host = {"platform_scope_id": scope, "os_family": platform.os_family, "os_version": platform.os_version, "architecture": platform.architecture, "native_mode": "native", "control_results": windows_controls(), **pin.__dict__}
        binding = windows_binding(fixture.mapping)
        self.assertEqual(len(verify_host_policy(host, fixture.mapping, scope, binding)), 21)
        host["os_build"] = "wrong"
        with self.assertRaisesRegex(AttestationFailure, "HOST_POLICY_MISMATCH"):
            verify_host_policy(host, fixture.mapping, scope, binding)

    def test_rejects_bool_profile_revision_before_equality(self) -> None:
        scope = "windows-11-24h2-x86_64-production"
        fixture = valid_profile_fixture(scope)
        fixture.profiles[0].payload["profile_revision"] = True
        with self.assertRaisesRegex(AttestationFailure, "PROFILE_MISMATCH"):
            verify_profile_rows(fixture.profiles, fixture.canaries, fixture.mapping, fixture.report, scope)


if __name__ == "__main__":
    unittest.main()
