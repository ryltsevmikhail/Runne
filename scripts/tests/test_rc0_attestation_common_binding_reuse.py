"""Cross-report evidence reuse negatives for the complete binding group."""

from __future__ import annotations

import hashlib
import unittest

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, verify_signed_envelope
from scripts.rc0_policy.platform_attestation import AttestationFailure, verify_platform_attestation
from scripts.rc0_policy.platform_policy_report import _common, _projection, verify_qualified_declaration
from scripts.tests import rc0_platform_envelope_support as envelope_support
from scripts.tests.rc0_platform_attestation_trust_support import digest, envelope, valid_attestation_fixture


def _report_store() -> tuple[AdjunctSchemaStore, object]:
    documents = dict(envelope_support._fixture_schema_store()._schemas)
    schema_id = "gocode.rc0.schema.verification-report/3"
    documents[schema_id] = (envelope_support._ROOT / "docs/schemas/rc0-verification-report-v3.schema.json").read_bytes()
    _, verifier = envelope_support.valid_fixture_envelope()
    return AdjunctSchemaStore(documents), verifier


def _successor(fixture: object, mutate) -> tuple[object, object, object]:
    report_outer = loads_canonical(fixture.report._canonical_report_envelope_bytes)
    report_payload = report_outer["payload"]
    mutate(report_payload)
    binding = _common(report_payload)
    for row in report_payload["required_gate_results"]:
        row["binding"] = loads_canonical(canonical_bytes(binding))
    report_outer["payload_sha256"] = digest(report_payload)
    report_raw = envelope_support._sign(report_outer)
    store, verifier = _report_store()
    report_envelope = verify_signed_envelope(report_raw, store, verifier, fixture.now_epoch_seconds)

    declaration_outer = loads_canonical(fixture.declaration._canonical_declaration_envelope_bytes)
    declaration_payload = declaration_outer["payload"]
    declaration_payload["common_binding_group"] = binding
    declaration_payload["common_binding_group_payload_sha256"] = digest(binding)
    declaration_payload["verification_report_envelope_sha256"] = report_envelope.envelope_sha256
    declaration_payload["required_gate_set_payload_sha256"] = _projection(report_payload, False)
    declaration_payload["artifact_set_payload_sha256"] = _projection(report_payload, True)
    declaration_envelope = envelope(declaration_payload, "gocode.rc0.qualified-declaration/1", "rc0_qualification_declarer")
    verify = lambda raw: verify_signed_envelope(raw, store, verifier, fixture.now_epoch_seconds)
    declaration = verify_qualified_declaration(
        declaration_envelope,
        loads_canonical(fixture.mapping.rc0_trust_policy.canonical_bytes),
        fixture.mapping,
        lambda value: report_raw if value == report_envelope.envelope_sha256 else b"",
        verify,
        fixture.now_epoch_seconds,
    )
    attestation_payload = loads_canonical(fixture.attestation.payload_canonical_bytes)
    attestation_payload["common_binding_group"] = binding
    attestation_payload["common_binding_group_payload_sha256"] = digest(binding)
    attestation = envelope(attestation_payload, "gocode.rc0.platform-scope-attestation/1", "qualification_aggregator")
    return declaration, declaration.report, attestation


class AttestationCommonBindingReuseTests(unittest.TestCase):
    def test_old_declaration_cannot_mix_with_successor_report(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        _, report_b, _ = _successor(fixture, lambda report: report.__setitem__("evidence_bundle_digest", "e" * 64))
        with self.assertRaisesRegex(AttestationFailure, "DECLARATION_VERIFIED_INVALID"):
            verify_platform_attestation(**{**fixture.arguments(), "report": report_b})

    def test_hybrid_report_reusing_classifier_pairs_and_host_rejects_before_view(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        declaration_b, report_b, attestation_b = _successor(fixture, lambda report: report.__setitem__("observed_evidence_revision", "e" * 40))
        with self.assertRaisesRegex(AttestationFailure, "EVIDENCE_LINEAGE_MISMATCH"):
            verify_platform_attestation(**{**fixture.arguments(), "attestation": attestation_b, "declaration": declaration_b, "report": report_b})

    def test_old_attestation_cannot_mix_with_successor_declaration_and_report(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        declaration_b, report_b, _ = _successor(fixture, lambda report: report.__setitem__("evidence_bundle_digest", "e" * 64))
        with self.assertRaisesRegex(AttestationFailure, "ATTESTATION_LINEAGE_MISMATCH"):
            verify_platform_attestation(**{**fixture.arguments(), "declaration": declaration_b, "report": report_b})

    def test_partial_artifact_slot_reuse_rejects_after_full_artifact_set_changes(self) -> None:
        fixture = valid_attestation_fixture("linux-ubuntu-24_04-x86_64-production")
        def add_artifact(report: dict[str, object]) -> None:
            report["exact_artifact_bindings"].append({"relative_path": "dist/other.tar", "sha256": "e" * 64, "size": 4, "locator": "cas:sha256:" + "e" * 64})
        declaration_b, report_b, attestation_b = _successor(fixture, add_artifact)
        with self.assertRaisesRegex(AttestationFailure, "EVIDENCE_LINEAGE_MISMATCH"):
            verify_platform_attestation(**{**fixture.arguments(), "attestation": attestation_b, "declaration": declaration_b, "report": report_b})


if __name__ == "__main__":
    unittest.main()
