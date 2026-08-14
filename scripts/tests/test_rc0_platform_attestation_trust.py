"""Authenticated integration boundary for platform attestations."""

from __future__ import annotations

import unittest
import weakref
from typing import get_type_hints
from dataclasses import replace
from unittest.mock import patch

from scripts.rc0_policy.activation import ActivationFailure, ActivationView
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.composite_canonical import canonical_composite_bytes, loads_composite_canonical
from scripts.rc0_policy.platform_attestation import AttestationFailure, PlatformAttestationView, verify_platform_attestation
from scripts.rc0_policy.platform_attestation_evidence import AttestationEvidenceBundle, HostIdentity, digests
from scripts.tests.rc0_platform_activation_support import reframed_envelope
from scripts.tests.rc0_platform_attestation_trust_support import envelope, valid_attestation_fixture


class PlatformAttestationTrustTests(unittest.TestCase):
    def test_verifies_linux_fixture(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        view = verify_platform_attestation(**fixture.arguments())
        self.assertEqual(view.platform_scope_id, "linux-ubuntu-24_04-x86_64-production")

    def test_verifies_each_declared_platform_scope(self) -> None:
        for scope in ("windows-11-24h2-x86_64-production", "macos-14-arm64-development-preview"):
            self.assertEqual(verify_platform_attestation(**valid_attestation_fixture(scope).arguments()).platform_scope_id, scope)

    def test_rejects_tampered_caller_evidence_bundle(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_EVIDENCE_SET_MISMATCH"):
            verify_platform_attestation(**{**fixture.arguments(), "evidence": replace(fixture.evidence, host_records=())})

    def test_replay_rejects_direct_construction(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        view = verify_platform_attestation(**fixture.arguments())
        with self.assertRaises(TypeError):
            type(view)(object())

    def test_activation_replay_precedes_bundle_validation(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        with patch.object(ActivationView, "require_verified", side_effect=ActivationFailure("ORDER")):
            with self.assertRaisesRegex(AttestationFailure, "ACTIVATION_VERIFIED_INVALID"):
                verify_platform_attestation(**{**fixture.arguments(), "evidence": object()})

    def test_replay_rejects_public_or_source_mutation(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        view = verify_platform_attestation(**fixture.arguments())
        object.__setattr__(view, "repository_id", "forged")
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)
        clean = verify_platform_attestation(**fixture.arguments())
        object.__setattr__(clean, "_canonical_source_bytes", b"forged")
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_VERIFIED_INVALID"):
            clean.require_verified(fixture.now_epoch_seconds)

    def test_view_is_closed_and_weak_referenceable(self) -> None:
        view = verify_platform_attestation(**valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production").arguments())
        self.assertFalse(hasattr(view, "__dict__"))
        self.assertIs(weakref.ref(view)(), view)

    def test_source_is_exact_composite_canonical_object(self) -> None:
        view = verify_platform_attestation(**valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production").arguments())
        self.assertEqual(canonical_composite_bytes(loads_composite_canonical(view._canonical_source_bytes)), view._canonical_source_bytes)

    def test_rejects_separately_minted_dependency_graph(self) -> None:
        first = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        second = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        with self.assertRaisesRegex(AttestationFailure, "ACTIVATION_VERIFIED_INVALID"):
            verify_platform_attestation(**{**first.arguments(), "mapping": second.mapping, "adjunct_trust": second.adjunct_trust})

    def test_outer_wrong_role_and_cross_category_are_trust_failures(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        payload = loads_composite_canonical(fixture.attestation.payload_canonical_bytes)
        wrong = envelope(payload, "gocode.rc0.platform-scope-attestation/1", "native_host_attestor")
        with self.assertRaises(AttestationFailure) as outer:
            verify_platform_attestation(**{**fixture.arguments(), "attestation": wrong})
        self.assertIsNone(outer.exception.gate_failure)
        mixed = replace(fixture.evidence, profile_records=fixture.evidence.host_records)
        with self.assertRaises(AttestationFailure) as category:
            verify_platform_attestation(**{**fixture.arguments(), "evidence": mixed})
        self.assertIsNone(category.exception.gate_failure)

    def test_outer_requires_sorted_unique_category_and_exact_canary_set(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        payload = loads_composite_canonical(fixture.attestation.payload_canonical_bytes)
        payload["artifact_measurements"] = list(reversed(payload["artifact_measurements"]))
        reordered = envelope(payload, "gocode.rc0.platform-scope-attestation/1", "qualification_aggregator")
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_EVIDENCE_SET_MISMATCH"):
            verify_platform_attestation(**{**fixture.arguments(), "attestation": reordered})
        payload = loads_composite_canonical(fixture.attestation.payload_canonical_bytes)
        payload["canary_evidence_records"] = [fixture.evidence.host_records[0].envelope_sha256]
        canary = envelope(payload, "gocode.rc0.platform-scope-attestation/1", "qualification_aggregator")
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_EVIDENCE_SET_MISMATCH"):
            verify_platform_attestation(**{**fixture.arguments(), "attestation": canary})

    def test_replay_rejects_bundle_container_pair_and_member_substitution(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        bundle = AttestationEvidenceBundle(list(fixture.evidence.classifier_pairs), list(fixture.evidence.host_records), list(fixture.evidence.profile_records), list(fixture.evidence.canary_records))
        view = verify_platform_attestation(**{**fixture.arguments(), "evidence": bundle})
        view.require_verified(fixture.now_epoch_seconds)
        bundle.host_records[0] = reframed_envelope(bundle.host_records[0], fixture.now_epoch_seconds)
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)
        bundle = AttestationEvidenceBundle(list(fixture.evidence.classifier_pairs), list(fixture.evidence.host_records), list(fixture.evidence.profile_records), list(fixture.evidence.canary_records))
        view = verify_platform_attestation(**{**fixture.arguments(), "evidence": bundle})
        bundle.classifier_pairs.reverse()
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)
        bundle = AttestationEvidenceBundle(list(fixture.evidence.classifier_pairs), list(fixture.evidence.host_records), list(fixture.evidence.profile_records), list(fixture.evidence.canary_records))
        view = verify_platform_attestation(**{**fixture.arguments(), "evidence": bundle})
        bundle.classifier_pairs[0] = (reframed_envelope(bundle.classifier_pairs[0][0], fixture.now_epoch_seconds), bundle.classifier_pairs[0][1])
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)

    def test_cardinality_precedes_authenticated_failed_control(self) -> None:
        fixture = valid_attestation_fixture("macos-14-arm64-development-preview")
        host = loads_canonical(fixture.evidence.host_records[0].payload_canonical_bytes)
        host["control_results"] = [{**row, "result": "FAILED"} if row["control_id"] == "macos_cleanup" else row for row in host["control_results"]]
        failed_host = envelope(host, "gocode.rc0.native-host-evidence-record/1", "native_host_attestor")
        extra = loads_canonical(fixture.evidence.canary_records[0].payload_canonical_bytes)
        extra["observed_at"] = "2023-11-14T22:13:21Z"; extra["freshness_deadline"] = "2023-11-14T22:13:25Z"
        extra_canary = envelope(extra, "gocode.rc0.canary-evidence-record/1", "external_canary_operator")
        evidence = replace(fixture.evidence, host_records=(failed_host,), canary_records=(fixture.evidence.canary_records[0], extra_canary))
        outer = loads_canonical(fixture.attestation.payload_canonical_bytes)
        outer["host_evidence_records"] = [failed_host.envelope_sha256]
        outer["canary_evidence_records"] = sorted(item.envelope_sha256 for item in evidence.canary_records)
        attestation = envelope(outer, "gocode.rc0.platform-scope-attestation/1", "qualification_aggregator")
        with self.assertRaises(AttestationFailure) as failed:
            verify_platform_attestation(**{**fixture.arguments(), "attestation": attestation, "evidence": evidence})
        self.assertIsNone(failed.exception.gate_failure)

    def test_replay_rejects_equal_public_row_and_container_replacement(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        def rejected(change: object) -> None:
            view = verify_platform_attestation(**fixture.arguments()); change(view)
            with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_VERIFIED_INVALID"):
                view.require_verified(fixture.now_epoch_seconds)
        rejected(lambda view: object.__setattr__(view, "host", replace(view.host)))
        rejected(lambda view: object.__setattr__(view, "attestation_issuer_identity", replace(view.attestation_issuer_identity)))
        rejected(lambda view: object.__setattr__(view.host, "host_attestor_identity", replace(view.host.host_attestor_identity)))
        rejected(lambda view: object.__setattr__(view, "closures", (replace(view.closures[0]), *view.closures[1:])))
        rejected(lambda view: object.__setattr__(view, "profile_rows", (replace(view.profile_rows[0]), *view.profile_rows[1:])))
        rejected(lambda view: object.__setattr__(view, "evidence_envelope_sha256s", tuple([*view.evidence_envelope_sha256s])))
        rejected(lambda view: object.__setattr__(view, "evidence_identities", (replace(view.evidence_identities[0]), *view.evidence_identities[1:])))

    def test_replay_runs_activation_before_evidence_identity_rejection(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        evidence = AttestationEvidenceBundle(list(fixture.evidence.classifier_pairs), list(fixture.evidence.host_records), list(fixture.evidence.profile_records), list(fixture.evidence.canary_records))
        view = verify_platform_attestation(**{**fixture.arguments(), "evidence": evidence})
        evidence.host_records[0] = reframed_envelope(evidence.host_records[0], fixture.now_epoch_seconds)
        with patch.object(ActivationView, "require_dependencies", side_effect=ActivationFailure("ORDER")) as check:
            with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_VERIFIED_INVALID"):
                view.require_verified(fixture.now_epoch_seconds)
        check.assert_called_once()

    def test_outer_freshness_uses_microseconds_and_never_mints_gate_failure(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        def rejected(payload_change: dict[str, str] | None = None, **envelope_change: object) -> None:
            payload = loads_canonical(fixture.attestation.payload_canonical_bytes); payload.update(payload_change or {})
            attestation = envelope(payload, "gocode.rc0.platform-scope-attestation/1", "qualification_aggregator") if payload_change else reframed_envelope(fixture.attestation, fixture.now_epoch_seconds, **envelope_change)
            with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_FRESHNESS_MISMATCH") as failed:
                verify_platform_attestation(**{**fixture.arguments(), "attestation": attestation, "now_epoch_seconds": fixture.now_epoch_seconds + 1})
            self.assertIsNone(failed.exception.gate_failure)
        rejected({"observed_at": "2023-11-14T22:13:20.000001Z"})
        rejected({"freshness_deadline": "2023-11-14T22:13:20.999999Z"})
        rejected(expires_at="2023-11-14T22:13:20.999999Z")

    def test_every_evidence_category_rejects_same_second_microsecond_inversion(self) -> None:
        cases = (("linux-ubuntu-24_04-x86_64-production", "artifact_measurements", "gocode.rc0.artifact-measurement-record/1", "artifact_classifier_a"), ("linux-ubuntu-24_04-x86_64-production", "host_evidence_records", "gocode.rc0.native-host-evidence-record/1", "native_host_attestor"), ("linux-ubuntu-24_04-x86_64-production", "profile_evidence_records", "gocode.rc0.profile-evidence-record/1", "native_host_attestor"), ("macos-14-arm64-development-preview", "canary_evidence_records", "gocode.rc0.canary-evidence-record/1", "external_canary_operator"))
        for scope, category, schema, role in cases:
            for field, value in (("observed_at", "2023-11-14T22:13:20.000001Z"), ("freshness_deadline", "2023-11-14T22:13:30.000001Z")):
                fixture = valid_attestation_fixture(scope); bundle = fixture.evidence
                attribute = category.replace("_evidence_records", "_records")
                original = bundle.classifier_pairs[0][0] if category == "artifact_measurements" else getattr(bundle, attribute)[0]
                payload = loads_canonical(original.payload_canonical_bytes); payload[field] = value; replacement = envelope(payload, schema, role)
                if category == "artifact_measurements": evidence = replace(bundle, classifier_pairs=((replacement, bundle.classifier_pairs[0][1]), *bundle.classifier_pairs[1:]))
                else: evidence = replace(bundle, **{attribute: (replacement, *getattr(bundle, attribute)[1:])})
                outer = loads_canonical(fixture.attestation.payload_canonical_bytes); outer[category] = list(dict(digests(evidence))[category])
                attestation = envelope(outer, "gocode.rc0.platform-scope-attestation/1", "qualification_aggregator")
                with self.assertRaisesRegex(AttestationFailure, "EVIDENCE_FRESHNESS_MISMATCH") as failed:
                    verify_platform_attestation(**{**fixture.arguments(), "attestation": attestation, "evidence": evidence})
                self.assertIsNone(failed.exception.gate_failure)

    def test_untrusted_missing_or_newline_outer_time_never_mints_gate_failure(self) -> None:
        for change in (("observed_at", None), ("freshness_deadline", "2023-11-14T22:13:25Z\n")):
            fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
            payload = loads_canonical(fixture.attestation.payload_canonical_bytes)
            if change[1] is None: payload.pop(change[0])
            else: payload[change[0]] = change[1]
            object.__setattr__(fixture.attestation, "payload_canonical_bytes", canonical_bytes(payload))
            with self.assertRaises(AttestationFailure) as failed:
                verify_platform_attestation(**fixture.arguments())
            self.assertIsNone(failed.exception.gate_failure)
    def test_host_identity_reflection_is_exact(self) -> None:
        self.assertEqual(tuple(HostIdentity.__dataclass_fields__), ("os_family", "os_version", "os_build", "kernel_or_image_sha256", "architecture", "native_mode", "backend_id", "backend_version", "probe_set_payload_sha256", "enforcement_descriptor_payload_sha256", "workflow_run_id", "observed_at", "freshness_deadline", "executed_artifacts", "control_results", "host_attestor_identity"))
        annotation = get_type_hints(HostIdentity)["control_results"]
        self.assertEqual(annotation.__args__[0].__name__, "HostControlResult")
        self.assertEqual(tuple(PlatformAttestationView.__dataclass_fields__), ("envelope_sha256", "repository_id", "attestation_issuer_identity", "mapping_policy_envelope_sha256", "rc0_qualification_policy_digest", "active_activation_snapshot_envelope_sha256", "common_binding_group_payload_sha256", "platform_scope_id", "qualification_class", "support_disposition", "host", "closures", "profile_rows", "evidence_envelope_sha256s", "evidence_identities", "_canonical_source_bytes", "_verification_token"))


if __name__ == "__main__":
    unittest.main()
