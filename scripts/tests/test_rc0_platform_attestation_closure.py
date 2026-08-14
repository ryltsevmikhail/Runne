"""Tests for the isolated structural artifact-closure boundary."""

from __future__ import annotations

import hashlib
import unittest

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import PrincipalBinding
from scripts.tests.rc0_platform_attestation_closure_support import (
    replace_host_payload, replace_host_profile, replace_measurement_identity,
    replace_measurement_payload, replace_measurement_profile, valid_closure_fixture,
)


def closure_module():
    try:
        from scripts.rc0_policy import artifact_closure
    except ImportError as error:
        raise AssertionError("artifact closure verifier is absent") from error
    return artifact_closure


class ArtifactClosureTests(unittest.TestCase):
    def verify(self, fixture):
        return closure_module().verify_artifact_closure(
            fixture.measurement_a, fixture.measurement_b, fixture.host_record
        )

    def assert_rejected(self, fixture, code: str) -> None:
        with self.assertRaises(closure_module().ArtifactClosureFailure) as raised:
            self.verify(fixture)
        self.assertEqual(raised.exception.code, code)

    def test_retains_complete_immutable_closure_for_each_slot(self) -> None:
        for slot in (
            "linux-appimage", "linux-deb", "windows-installer-unsigned",
            "macos-app-development-adhoc", "macos-dmg-development-adhoc",
        ):
            with self.subTest(slot=slot):
                fixture = valid_closure_fixture(slot)
                closure = self.verify(fixture)
                self.assertEqual(closure.artifact_slot_id, slot)
                self.assertEqual(closure.classifier_run_ids, ("classifier-a-run", "classifier-b-run"))
                self.assertEqual(closure.classifier_identities[0].lane_id, "classifier-a")
                with self.assertRaises(AttributeError):
                    closure.artifact_slot_id = "other"

    def test_rejects_one_classifier_manifest_lie(self) -> None:
        fixture = valid_closure_fixture("linux-appimage")
        lying = replace_measurement_payload(fixture.measurement_a, artifact_manifest_payload_sha256="e" * 64)
        self.assert_rejected(fixture.__class__(lying, fixture.measurement_b, fixture.host_record), "CLASSIFIER_MANIFEST_MISMATCH")

    def test_rejects_classifier_identity_lane_implementation_dependency_or_run_overlap(self) -> None:
        fixture = valid_closure_fixture("linux-deb")
        cases = {
            "lane": {"classifier_lane_id": "classifier-a"},
            "implementation": {"classifier_implementation_sha256": "7" * 64},
            "dependency": {"classifier_dependency_set_sha256": "9" * 64},
            "run": {"classifier_run_id": "classifier-a-run"},
        }
        for name, changes in cases.items():
            with self.subTest(name=name):
                changed = replace_measurement_payload(fixture.measurement_b, **changes)
                self.assert_rejected(fixture.__class__(fixture.measurement_a, changed, fixture.host_record), "CLASSIFIER_DIVERSITY_MISMATCH")
        for field in ("issuer_subject_id", "issuer_controlling_account_id", "issuer_delegated_session_id"):
            with self.subTest(identity=field):
                envelope = fixture.measurement_b
                original = getattr(envelope, field)
                object.__setattr__(envelope, field, getattr(fixture.measurement_a, field))
                self.assert_rejected(fixture, "FIXTURE_ENVELOPE_INVALID")
                object.__setattr__(envelope, field, original)

    def test_rejects_cross_field_classifier_principal_collision(self) -> None:
        fixture = valid_closure_fixture("linux-appimage")
        collided = replace_measurement_identity(
            fixture.measurement_b,
            issuer_controlling_account_id=fixture.measurement_a.issuer_subject_id,
        )
        self.assert_rejected(fixture.__class__(fixture.measurement_a, collided, fixture.host_record), "CLASSIFIER_DIVERSITY_MISMATCH")

    def test_rejects_nonprimitive_issuer_role_and_retained_principal(self) -> None:
        class AlwaysEqual:
            def __eq__(self, other: object) -> bool:
                return True

            def __ne__(self, other: object) -> bool:
                return False

            def __hash__(self) -> int:
                return 0

        class StringSubclass(str):
            pass

        fixture = valid_closure_fixture("linux-appimage")
        envelope, principal = fixture.measurement_b, fixture.measurement_b.trust.principal
        for value in (AlwaysEqual(), StringSubclass("artifact_classifier_b")):
            with self.subTest(value=type(value).__name__):
                role = envelope.issuer_role
                object.__setattr__(envelope, "issuer_role", value)
                object.__setattr__(envelope.trust, "principal", PrincipalBinding(value, principal.subject_id, principal.controlling_account_id, principal.delegated_session_id, principal.lane_id))
                self.assert_rejected(fixture, "FIXTURE_ENVELOPE_INVALID")
                object.__setattr__(envelope, "issuer_role", role)
                object.__setattr__(envelope.trust, "principal", principal)

    def test_rejects_nonprimitive_measurement_or_host_schema_selector(self) -> None:
        class AlwaysEqual:
            def __eq__(self, other: object) -> bool:
                return True

            def __ne__(self, other: object) -> bool:
                return False

        class StringSubclass(str):
            pass

        for record in ("measurement_b", "host_record"):
            for kind in ("AlwaysEqual", "StringSubclass"):
                with self.subTest(record=record, value=kind):
                    fixture = valid_closure_fixture("linux-appimage")
                    envelope = getattr(fixture, record)
                    original = envelope.payload_schema_id
                    value = AlwaysEqual() if kind == "AlwaysEqual" else StringSubclass(original)
                    object.__setattr__(envelope, "payload_schema_id", value)
                    self.assert_rejected(fixture, "FIXTURE_ENVELOPE_INVALID")
                    object.__setattr__(envelope, "payload_schema_id", original)

    def test_rejects_every_mutable_lineage_field_on_measurement_or_host(self) -> None:
        fixture = valid_closure_fixture("windows-installer-unsigned")
        fields = (
            "mapping_policy_envelope_sha256", "adjunct_trust_registry_envelope_sha256",
            "adjunct_trust_registry_payload_sha256", "rc0_qualification_policy_digest",
            "active_activation_snapshot_envelope_sha256", "common_binding_group",
            "common_binding_group_payload_sha256", "platform_scope_id",
        )
        for source, replace in (("measurement", replace_measurement_payload), ("host", replace_host_payload)):
            for field in fields:
                with self.subTest(source=source, field=field):
                    payload = loads_canonical((fixture.measurement_b if source == "measurement" else fixture.host_record).payload_canonical_bytes)
                    if field in {"common_binding_group", "common_binding_group_payload_sha256"}:
                        payload["common_binding_group"]["evidence_attempt_id"] = "018f0000-0000-7000-8000-000000000001"
                        payload["common_binding_group_payload_sha256"] = hashlib.sha256(canonical_bytes(payload["common_binding_group"])).hexdigest()
                    elif field == "platform_scope_id":
                        payload[field] = "linux-ubuntu-24_04-x86_64-production"
                    else:
                        payload[field] = "f" * 64
                    changed = replace(fixture.measurement_b if source == "measurement" else fixture.host_record, **payload)
                    candidate = fixture.__class__(fixture.measurement_a, changed, fixture.host_record) if source == "measurement" else fixture.__class__(fixture.measurement_a, fixture.measurement_b, changed)
                    self.assert_rejected(candidate, "LINEAGE_INVALID" if field == "rc0_qualification_policy_digest" else "LINEAGE_MISMATCH")

    def test_rejects_re_signed_measurement_or_host_self_lineage_policy_and_profile(self) -> None:
        fixture = valid_closure_fixture("windows-installer-unsigned")
        for source, replace, replace_profile in (
            ("measurement", replace_measurement_payload, replace_measurement_profile),
            ("host", replace_host_payload, replace_host_profile),
        ):
            record = fixture.measurement_b if source == "measurement" else fixture.host_record
            for name, changed in (
                ("policy", replace(record, rc0_qualification_policy_digest="f" * 64)),
                ("profile", replace_profile(record, "gocode.rc0.evidence-profile/2")),
            ):
                with self.subTest(source=source, name=name):
                    candidate = fixture.__class__(fixture.measurement_a, changed, fixture.host_record) if source == "measurement" else fixture.__class__(fixture.measurement_a, fixture.measurement_b, changed)
                    self.assert_rejected(candidate, "LINEAGE_INVALID")

    def test_rejects_noncanonical_or_nonclosed_host_slot_inventory(self) -> None:
        fixture = valid_closure_fixture("linux-appimage")
        original = loads_canonical(fixture.host_record.payload_canonical_bytes)["executed_artifacts"]
        extra = dict(original[0], artifact_slot_id="windows-installer-unsigned", artifact_kind="msi", relative_path="dist/extra", sha256="e" * 64, locator="cas:sha256:" + "e" * 64)
        duplicate_slot = [dict(row) for row in original]
        duplicate_slot[1]["artifact_slot_id"] = duplicate_slot[0]["artifact_slot_id"]
        duplicate_raw = [dict(row) for row in original]
        duplicate_raw[1].update({name: duplicate_raw[0][name] for name in ("relative_path", "sha256", "size", "locator")})
        cases = {
            "unsorted": list(reversed(original)), "missing": original[:1], "extra": [*original, extra],
            "duplicate-slot": duplicate_slot, "duplicate-raw": duplicate_raw,
        }
        for name, rows in cases.items():
            with self.subTest(name=name):
                changed = replace_host_payload(fixture.host_record, executed_artifacts=rows)
                self.assert_rejected(fixture.__class__(fixture.measurement_a, fixture.measurement_b, changed), "HOST_ARTIFACT_MISMATCH")

    def test_rejects_raw_tuple_manifest_or_host_binding_mismatch(self) -> None:
        fixture = valid_closure_fixture("windows-installer-unsigned")
        changed = loads_canonical(fixture.measurement_b.payload_canonical_bytes)
        changed["relative_path"] = "dist/other"
        changed["artifact_manifest_payload"]["raw_artifact"]["relative_path"] = "dist/other"
        changed["artifact_manifest_payload_sha256"] = hashlib.sha256(canonical_bytes(changed["artifact_manifest_payload"])).hexdigest()
        raw_lie = replace_measurement_payload(fixture.measurement_b, **changed)
        self.assert_rejected(fixture.__class__(fixture.measurement_a, raw_lie, fixture.host_record), "ARTIFACT_TUPLE_MISMATCH")
        host_payload = loads_canonical(fixture.host_record.payload_canonical_bytes)
        host_payload["executed_artifacts"][0]["product_manifest_payload_sha256"] = "f" * 64
        host_lie = replace_host_payload(fixture.host_record, **host_payload)
        self.assert_rejected(fixture.__class__(fixture.measurement_a, fixture.measurement_b, host_lie), "HOST_ARTIFACT_MISMATCH")

    def test_rejects_noncanonical_manifest_inventory_or_missing_host_row(self) -> None:
        fixture = valid_closure_fixture("macos-app-development-adhoc")
        payload = loads_canonical(fixture.measurement_a.payload_canonical_bytes)
        manifest = payload["artifact_manifest_payload"]
        manifest["entries"].append({"relative_path": "bin/gocode", "sha256": "e" * 64, "size": 1, "mode": "0644", "executable_architecture": "arm64", "entitlement_capability_descriptor_sha256": "f" * 64, "role": "resource"})
        payload["artifact_manifest_payload_sha256"] = hashlib.sha256(canonical_bytes(manifest)).hexdigest()
        malformed = replace_measurement_payload(fixture.measurement_a, **payload)
        self.assert_rejected(fixture.__class__(malformed, fixture.measurement_b, fixture.host_record), "ARTIFACT_MANIFEST_INVALID")
        host_payload = loads_canonical(fixture.host_record.payload_canonical_bytes)
        host_payload["executed_artifacts"][0]["artifact_slot_id"] = "macos-dmg-development-adhoc"
        host_lie = replace_host_payload(fixture.host_record, **host_payload)
        self.assert_rejected(fixture.__class__(fixture.measurement_a, fixture.measurement_b, host_lie), "HOST_ARTIFACT_MISMATCH")


if __name__ == "__main__":
    unittest.main()
