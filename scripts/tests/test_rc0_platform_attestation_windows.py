"""Windows control semantics for fixture-only platform attestations."""

from __future__ import annotations

import unittest

from scripts.rc0_policy.platform_attestation_profiles import (
    AttestationGateBinding,
    AttestationFailure,
    verify_shape_results,
    verify_host_controls,
)
from scripts.rc0_policy.outcomes import (
    OUTCOME_TRUST_DOMAIN,
    OperationalTrustVerification,
    normalize_verified_required_gate_results,
    verify_required_gate_results,
)
from scripts.tests.rc0_platform_attestation_windows_support import windows_binding, windows_controls
from scripts.tests.rc0_platform_attestation_profiles_support import valid_profile_fixture


class WindowsControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mapping = valid_profile_fixture("windows-11-24h2-x86_64-production").mapping
        self.binding = windows_binding(self.mapping)

    def test_failure_uses_authenticated_production_gate_and_full_gate_set(self) -> None:
        with self.assertRaises(AttestationFailure) as raised:
            verify_host_controls(windows_controls(failed="windows_owner_acl"), "Windows", self.binding, self.mapping)
        failure = raised.exception.gate_failure
        production = next(row[0] for row in self.mapping.rc0_trust_policy.required_gate_projection if row[1] == "PRODUCTION_QUALIFICATION")
        self.assertEqual(failure.gate_id, production)
        stages = {row[0]: row[1] for row in self.mapping.rc0_trust_policy.required_gate_projection}
        raw = []
        for gate_id in self.mapping.required_gate_ids:
            row = {"gate_id": gate_id, "stage": stages[gate_id], "execution_outcome": "PASS", "gate_result": "PASS", "binding": failure.binding.__dict__}
            if gate_id == failure.gate_id:
                row.update(execution_outcome=failure.execution_outcome, gate_result=failure.gate_result, blocked_reason=failure.blocked_reason)
            raw.append(row)
        def trusted(_snapshot: object, transcript: bytes) -> OperationalTrustVerification:
            import hashlib
            return OperationalTrustVerification("FIXTURE_ONLY", hashlib.sha256(transcript).hexdigest(), hashlib.sha256(transcript[len(OUTCOME_TRUST_DOMAIN):]).hexdigest())
        verified = verify_required_gate_results(raw, trusted)
        self.assertEqual(normalize_verified_required_gate_results(verified, self.mapping.required_gate_ids, failure.binding.__dict__), "BLOCKED(REQUIRED_GATE_FAILED)")

    def test_shape_failures_use_production_gate_for_all_platforms(self) -> None:
        for scope_id, slot_id, applicable in (("linux-ubuntu-24_04-x86_64-production", "linux-appimage", "linux_product_payload"), ("windows-11-24h2-x86_64-production", "windows-installer-unsigned", "windows_helper"), ("macos-14-arm64-development-preview", "macos-app-development-adhoc", "macos_app_dmg")):
            mapping = valid_profile_fixture(scope_id).mapping
            binding = windows_binding(mapping, scope_id)
            for result, outcome in (("FAILED", "FAIL"), ("NOT_APPLICABLE", "NOT_RUN")):
                shapes = {"path_normalization": "PASS", "traversal": "PASS", "symlink": "PASS", "hardlink": "PASS", "special_file": "PASS", "case_collision": "PASS", "unlisted_package_script": "PASS", "linux_product_payload": "NOT_APPLICABLE", "windows_helper": "NOT_APPLICABLE", "macos_app_dmg": "NOT_APPLICABLE"}
                shapes[applicable] = result
                with self.subTest(slot_id=slot_id, result=result), self.assertRaises(AttestationFailure) as raised:
                    verify_shape_results(shapes, slot_id, binding, mapping)
                self.assertEqual(raised.exception.gate_failure.execution_outcome, outcome)
    def test_windows_requires_owner_acl_and_dacl_evidence(self) -> None:
        rows = windows_controls(failed="windows_owner_acl")
        with self.assertRaisesRegex(AttestationFailure, "windows_owner_acl") as raised:
            verify_host_controls(rows, "Windows", self.binding, self.mapping)
        self.assertEqual(raised.exception.gate_failure.execution_outcome, "FAIL")
        self.assertEqual(raised.exception.gate_failure.blocked_reason, "REQUIRED_GATE_FAILED")
        failure = raised.exception.gate_failure
        raw = {
            "gate_id": failure.gate_id, "stage": failure.stage,
            "execution_outcome": failure.execution_outcome, "gate_result": failure.gate_result,
            "blocked_reason": failure.blocked_reason, "binding": failure.binding.__dict__,
        }
        def trusted(_snapshot: object, transcript: bytes) -> OperationalTrustVerification:
            import hashlib
            return OperationalTrustVerification("FIXTURE_ONLY", hashlib.sha256(transcript).hexdigest(), hashlib.sha256(transcript[len(OUTCOME_TRUST_DOMAIN):]).hexdigest())
        verified = verify_required_gate_results([raw], trusted)
        self.assertEqual(normalize_verified_required_gate_results(verified, [failure.gate_id], raw["binding"]), "BLOCKED(REQUIRED_GATE_FAILED)")

    def test_windows_requires_reparse_safe_protected_transport(self) -> None:
        with self.assertRaisesRegex(AttestationFailure, "windows_reparse_safe"):
            verify_host_controls(windows_controls(failed="windows_reparse_safe"), "Windows", self.binding, self.mapping)

    def test_windows_requires_real_appcontainer_and_job_object_cleanup(self) -> None:
        for control_id in ("windows_appcontainer", "windows_job_object_cleanup"):
            with self.subTest(control_id=control_id), self.assertRaisesRegex(AttestationFailure, control_id):
                verify_host_controls(windows_controls(failed=control_id), "Windows", self.binding, self.mapping)

    def test_windows_requires_direct_egress_denial_on_client_24h2(self) -> None:
        with self.assertRaisesRegex(AttestationFailure, "windows_direct_egress_denial"):
            verify_host_controls(windows_controls(not_applicable="windows_direct_egress_denial"), "Windows", self.binding, self.mapping)

    def test_shape_result_applicability_is_exact_per_slot(self) -> None:
        shapes = {"path_normalization": "PASS", "traversal": "PASS", "symlink": "PASS", "hardlink": "PASS", "special_file": "PASS", "case_collision": "PASS", "unlisted_package_script": "PASS", "linux_product_payload": "NOT_APPLICABLE", "windows_helper": "PASS", "macos_app_dmg": "NOT_APPLICABLE"}
        verify_shape_results(shapes, "windows-installer-unsigned", self.binding, self.mapping)
        shapes["macos_app_dmg"] = "PASS"
        with self.assertRaisesRegex(AttestationFailure, "ARTIFACT_SHAPE_MISMATCH"):
            verify_shape_results(shapes, "windows-installer-unsigned", self.binding, self.mapping)

    def test_rejects_always_equal_shape_value_before_comparison(self) -> None:
        class AlwaysEqual:
            def __eq__(self, _other: object) -> bool: return True
        shapes = {"path_normalization": AlwaysEqual(), "traversal": "PASS", "symlink": "PASS", "hardlink": "PASS", "special_file": "PASS", "case_collision": "PASS", "unlisted_package_script": "PASS", "linux_product_payload": "NOT_APPLICABLE", "windows_helper": "PASS", "macos_app_dmg": "NOT_APPLICABLE"}
        with self.assertRaisesRegex(AttestationFailure, "ARTIFACT_SHAPE_MISMATCH"):
            verify_shape_results(shapes, "windows-installer-unsigned", self.binding, self.mapping)

    def test_linux_binding_cannot_mint_a_windows_gate_failure(self) -> None:
        binding = windows_binding(self.mapping, "linux-ubuntu-24_04-x86_64-production")
        with self.assertRaises(AttestationFailure) as raised:
            verify_host_controls(windows_controls(failed="windows_owner_acl"), "Windows", binding, self.mapping)
        self.assertIsNone(raised.exception.gate_failure)

    def test_unrelated_mapping_sha_cannot_mint_a_gate_failure(self) -> None:
        binding = AttestationGateBinding("gocode", "f" * 64, "b" * 64, "c" * 64, "windows-11-24h2-x86_64-production")
        with self.assertRaises(AttestationFailure) as raised:
            verify_host_controls(windows_controls(failed="windows_owner_acl"), "Windows", binding, self.mapping)
        self.assertIsNone(raised.exception.gate_failure)

    def test_malformed_mapping_rows_cannot_mint_a_gate_failure(self) -> None:
        class AlwaysEqual:
            def __eq__(self, _other: object) -> bool: return True
        class StringSubclass(str): pass
        vectors = (("platform_scopes", "platform_scope_id", AlwaysEqual()), ("host_identity_pins", "platform_scope_id", AlwaysEqual()), ("host_identity_pins", "platform_scope_id", StringSubclass("windows-11-24h2-x86_64-production")), ("profile_states", "profile_revision", True))
        for collection, field, value in vectors:
            with self.subTest(collection=collection, field=field):
                mapping = valid_profile_fixture("windows-11-24h2-x86_64-production").mapping
                row = next(item for item in getattr(mapping, collection) if item.platform_scope_id == "windows-11-24h2-x86_64-production")
                object.__setattr__(row, field, value)
                with self.assertRaises(AttestationFailure) as raised:
                    verify_host_controls(windows_controls(failed="windows_owner_acl"), "Windows", windows_binding(mapping), mapping)
                self.assertIsNone(raised.exception.gate_failure)


if __name__ == "__main__":
    unittest.main()
