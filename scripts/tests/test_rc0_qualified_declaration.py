"""Fixture-only qualified-declaration report-binding tests."""
import dataclasses
import gc
import hashlib
import inspect
import unittest
import weakref

from scripts.rc0_policy.platform_policy import PolicyFailure, fixture_verify_mapping_policy, verify_qualified_declaration
from scripts.rc0_policy.platform_policy_report import ReportArtifactBinding, RequiredGateResultRow, _projection, validate_report_against_policy
from scripts.rc0_policy.external_envelope import AdjunctSchemaStore, verify_signed_envelope
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.tests.rc0_platform_policy_support import replace_declaration_field, valid_declaration_fixture, valid_mapping_fixture
from scripts.tests import rc0_platform_envelope_support as envelope_support

def _alternate_schema_envelope(envelope, schema_id: str):
    outer = loads_canonical(envelope.envelope_canonical_bytes)
    documents = dict(envelope_support._fixture_schema_store()._schemas)
    filename = {
        "gocode.rc0.qualified-declaration/1": "rc0-qualified-declaration-v1.schema.json",
        "gocode.rc0.schema.verification-report/3": "rc0-verification-report-v3.schema.json",
    }[schema_id]
    documents[schema_id] = (envelope_support._ROOT / "docs/schemas" / filename).read_bytes() + b"\n"
    outer["payload_schema_sha256"] = hashlib.sha256(documents[schema_id]).hexdigest()
    raw = envelope_support._sign(outer)
    _, verifier = envelope_support.valid_fixture_envelope()
    return verify_signed_envelope(raw, AdjunctSchemaStore(documents), verifier, envelope_support._NOW)

def _resigned_report(envelope, mutate):
    outer = loads_canonical(envelope.envelope_canonical_bytes)
    payload = outer["payload"]
    mutate(payload)
    outer["payload_sha256"] = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    documents = dict(envelope_support._fixture_schema_store()._schemas)
    documents["gocode.rc0.schema.verification-report/3"] = (envelope_support._ROOT / "docs/schemas/rc0-verification-report-v3.schema.json").read_bytes()
    _, verifier = envelope_support.valid_fixture_envelope()
    return verify_signed_envelope(envelope_support._sign(outer), AdjunctSchemaStore(documents), verifier, envelope_support._NOW)

class DeclarationTests(unittest.TestCase):
    def test_declaration_wraps_existing_report_with_domain_projections(self) -> None:
        fixture = valid_declaration_fixture()
        verified = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        self.assertEqual(verified.report.envelope_sha256, fixture.report.envelope_sha256)
    def test_missing_report_is_an_operational_failure(self) -> None:
        fixture = valid_declaration_fixture()
        with self.assertRaisesRegex(PolicyFailure, "REPORT_ENVELOPE_UNAVAILABLE"):
            verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, lambda _: b"", fixture.verify_envelope, fixture.now_epoch_seconds)
    def test_rejects_report_gate_artifact_or_policy_substitution(self) -> None:
        fixture = valid_declaration_fixture()
        for field in ("verification_report_envelope_sha256", "required_gate_set_payload_sha256", "artifact_set_payload_sha256", "rc0_qualification_policy_digest"):
            with self.subTest(field=field), self.assertRaises(PolicyFailure):
                changed = replace_declaration_field(fixture.declaration, field, "f" * 64)
                verify_qualified_declaration(changed, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
    def test_report_raw_and_verified_envelope_digest_both_equal_reference(self) -> None:
        fixture = valid_declaration_fixture()
        declaration = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        self.assertEqual(declaration.report.envelope_sha256, fixture.report.envelope_sha256)
    def test_report_declaration_direct_construction_replace_or_source_drift_rejects(self) -> None:
        from scripts.rc0_policy.platform_policy import VerifiedDeclaration, VerifiedReport
        from scripts.rc0_policy.platform_policy_report import _TOKEN
        fixture = valid_declaration_fixture()
        view = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        for owned in (view.report, view):
            self.assertFalse(hasattr(owned, "__dict__")); self.assertIs(weakref.ref(owned)(), owned)
            with self.assertRaises((AttributeError, TypeError)): object.__setattr__(owned, "require_verified", lambda _: None)
        for kind in (VerifiedReport, VerifiedDeclaration):
            with self.subTest(kind=kind), self.assertRaises(TypeError): kind()
        with self.assertRaises(TypeError): dataclasses.replace(view, repository_id="other")
        fields = {name: getattr(view.report, name) for name in view.report.__dataclass_fields__ if name != "_verification_token"}
        forged = VerifiedReport(_TOKEN, **fields)
        with self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
            forged.require_verified(fixture.now_epoch_seconds)
        object.__setattr__(view.report, "repository_id", "other")
        with self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
            view.report.require_verified(fixture.now_epoch_seconds)
        clean = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        object.__setattr__(clean.report, "_canonical_report_envelope_bytes", b"{}")
        with self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
            clean.report.require_verified(fixture.now_epoch_seconds)

    def test_policy_view_and_replay_are_exact(self) -> None:
        fixture = valid_declaration_fixture()
        with self.assertRaisesRegex(PolicyFailure, "RC0_MAPPING_SET_MISMATCH"):
            verify_qualified_declaration(fixture.declaration, {}, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        altered = dataclasses.replace(fixture.mapping.rc0_trust_policy, canonical_sha256="0" * 64)
        with self.assertRaisesRegex(PolicyFailure, "RC0_MAPPING_SET_MISMATCH"):
            validate_report_against_policy(fixture.report, altered, fixture.mapping, fixture.now_epoch_seconds)
        view = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds + 20)

    def test_report_and_declaration_revalidate_the_issued_mapping_dependency(self) -> None:
        fixture = valid_declaration_fixture()
        report = validate_report_against_policy(fixture.report, fixture.mapping.rc0_trust_policy, fixture.mapping, fixture.now_epoch_seconds)
        declaration = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        object.__setattr__(fixture.mapping.adjunct_trust, "expires_at_epoch_seconds", fixture.now_epoch_seconds - 1)
        with self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
            report.require_verified(fixture.now_epoch_seconds)
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
            declaration.require_verified(fixture.now_epoch_seconds)

    def test_issued_views_keep_mapping_alive_until_the_view_is_released(self) -> None:
        def issue_views():
            fixture = valid_declaration_fixture()
            report = validate_report_against_policy(fixture.report, fixture.mapping.rc0_trust_policy, fixture.mapping, fixture.now_epoch_seconds)
            declaration = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
            return report, declaration, fixture.now_epoch_seconds

        report, declaration, now = issue_views()
        gc.collect()
        report.require_verified(now)
        declaration.require_verified(now)

    def test_verified_view_public_time_parameter_supports_keywords(self) -> None:
        fixture = valid_declaration_fixture()
        report = validate_report_against_policy(fixture.report, fixture.mapping.rc0_trust_policy, fixture.mapping, fixture.now_epoch_seconds)
        declaration = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        for method in (fixture.mapping.require_verified, report.require_verified, declaration.require_verified):
            self.assertEqual(tuple(inspect.signature(method).parameters), ("now_epoch_seconds",))
            method(now_epoch_seconds=fixture.now_epoch_seconds)

    def test_public_facade_exports_every_task_four_interface(self) -> None:
        from scripts.rc0_policy import platform_policy

        expected = {
            "HostPolicyRow", "ReportArtifactBinding", "RequiredGateResultRow",
            "VerifiedDeclaration", "VerifiedMappingPolicy", "VerifiedReport",
            "parse_accepted_adr", "validate_report_against_policy",
            "fixture_verify_mapping_policy", "verify_qualified_declaration",
        }
        self.assertLessEqual(expected, set(platform_policy.__all__))
        for name in expected:
            self.assertIs(getattr(platform_policy, name), platform_policy.__dict__[name])

    def test_verified_view_contract_reflection_uses_identity_and_closed_fields(self) -> None:
        from scripts.rc0_policy.platform_policy import VerifiedDeclaration, VerifiedMappingPolicy, VerifiedReport

        expected = {
            VerifiedMappingPolicy: ("envelope_sha256", "adjunct_trust_registry_envelope_sha256", "adjunct_trust_registry_payload_sha256", "adjunct_trust", "rc0_qualification_policy_digest", "shared_decision_payload_sha256", "claim_registry_payload_sha256", "base_document_universe_payload_sha256", "classified_delta_payload_sha256", "composed_document_universe_payload_sha256", "activation_epoch", "platform_scopes", "artifact_slots", "profile_states", "host_identity_pins", "required_gate_ids", "rc0_trust_policy", "mapping_authority", "governance_authorities", "authority_roles", "adjunct_schema_digests", "_canonical_source_bytes", "_verification_token"),
            VerifiedReport: ("envelope_sha256", "repository_id", "reporter_identity", "common_binding_group_payload_sha256", "rc0_qualification_policy_digest", "required_gate_set_payload_sha256", "artifact_set_payload_sha256", "required_gate_results", "artifact_bindings", "_canonical_report_envelope_bytes", "_verification_token"),
            VerifiedDeclaration: ("envelope_sha256", "repository_id", "declarer_identity", "common_binding_group_payload_sha256", "rc0_qualification_policy_digest", "verification_report_envelope_sha256", "required_gate_set_payload_sha256", "artifact_set_payload_sha256", "report", "_canonical_declaration_envelope_bytes", "_verification_token"),
        }
        for kind, fields in expected.items():
            self.assertIs(kind.__dataclass_params__.eq, False)
            self.assertEqual(tuple(kind.__dataclass_fields__), fields)
        self.assertTrue(RequiredGateResultRow.__dataclass_params__.frozen)
        self.assertEqual(tuple(RequiredGateResultRow.__dataclass_fields__), ("gate_id", "stage", "execution_outcome", "gate_result", "blocked_reason", "canonical_row_bytes"))
        self.assertTrue(ReportArtifactBinding.__dataclass_params__.frozen)
        self.assertEqual(tuple(ReportArtifactBinding.__dataclass_fields__), ("relative_path", "sha256", "size", "locator"))
        first_mapping, second_mapping = valid_mapping_fixture(), valid_mapping_fixture()
        self.assertNotEqual(fixture_verify_mapping_policy(**first_mapping.arguments()), fixture_verify_mapping_policy(**second_mapping.arguments()))
        fixture = valid_declaration_fixture()
        first_report = validate_report_against_policy(fixture.report, fixture.mapping.rc0_trust_policy, fixture.mapping, fixture.now_epoch_seconds)
        second_report = validate_report_against_policy(fixture.report, fixture.mapping.rc0_trust_policy, fixture.mapping, fixture.now_epoch_seconds)
        self.assertNotEqual(first_report, second_report)
        first_declaration = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        second_declaration = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        self.assertNotEqual(first_declaration, second_declaration)

    def test_report_projections_are_exact_immutable_and_replayed(self) -> None:
        fixture = valid_declaration_fixture()
        report = validate_report_against_policy(
            fixture.report,
            fixture.mapping.rc0_trust_policy,
            fixture.mapping,
            fixture.now_epoch_seconds,
        )
        binding = {
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
        expected_gates = tuple(
            RequiredGateResultRow(
                gate_id,
                stage,
                "PASS",
                "PASS",
                None,
                canonical_bytes({
                    "gate_id": gate_id,
                    "stage": stage,
                    "execution_outcome": "PASS",
                    "gate_result": "PASS",
                    "binding": binding,
                }),
            )
            for gate_id, stage in (
                ("fixture-production-test", "PRODUCTION_QUALIFICATION"),
                ("fixture-source-test", "SOURCE_CANDIDATE"),
            )
        )
        expected_artifacts = (
            ReportArtifactBinding(
                "dist/gocode.tar",
                "f" * 64,
                3,
                "cas:sha256:" + "f" * 64,
            ),
        )
        self.assertEqual(report.required_gate_results, expected_gates)
        self.assertEqual(report.artifact_bindings, expected_artifacts)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.required_gate_results[0].gate_id = "changed"
        for field, changed in (("required_gate_results", ()), ("artifact_bindings", ())):
            original = getattr(report, field)
            object.__setattr__(report, field, changed)
            with self.subTest(field=field), self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
                report.require_verified(fixture.now_epoch_seconds)
            object.__setattr__(report, field, original)

    def test_replay_rejects_equal_looking_rows_principals_and_nested_report(self) -> None:
        equal_looking = lambda **fields: type("EqualLooking", (), {"__eq__": lambda *_: True, **fields})()
        fixture = valid_declaration_fixture(); declaration = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds); report = declaration.report
        for field, replacement in (
            ("required_gate_results", (equal_looking(canonical_row_bytes=b"changed"), *report.required_gate_results[1:])),
            ("artifact_bindings", (equal_looking(relative_path="changed", locator="cas:changed"),)),
            ("reporter_identity", equal_looking(subject_id="changed")),
        ):
            original = getattr(report, field); object.__setattr__(report, field, replacement)
            with self.subTest(field=field), self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
                report.require_verified(fixture.now_epoch_seconds)
            object.__setattr__(report, field, original)
        for field, replacement in (("declarer_identity", equal_looking(subject_id="changed")), ("report", equal_looking(envelope_sha256=report.envelope_sha256))):
            original = getattr(declaration, field); object.__setattr__(declaration, field, replacement)
            with self.subTest(field=field), self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
                declaration.require_verified(fixture.now_epoch_seconds)
            object.__setattr__(declaration, field, original)

    def test_replay_after_prerequisite_expiry_rejects_report_and_declaration(self) -> None:
        fixture = valid_declaration_fixture()
        report = validate_report_against_policy(fixture.report, fixture.mapping.rc0_trust_policy, fixture.mapping, fixture.now_epoch_seconds)
        declaration = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        later = fixture.now_epoch_seconds + 20
        with self.assertRaisesRegex(PolicyFailure, "MAPPING_.*INVALID"):
            fixture.mapping.require_verified(later)
        with self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
            report.require_verified(later)
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
            declaration.require_verified(later)

    def test_post_issuance_nested_report_substitution_rejects(self) -> None:
        fixture = valid_declaration_fixture()
        first = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        second = verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        object.__setattr__(first, "report", second.report)
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
            first.require_verified(fixture.now_epoch_seconds)

    def test_rejects_same_id_alternate_schema_and_resolver_substitution(self) -> None:
        fixture = valid_declaration_fixture()
        alternate_declaration = _alternate_schema_envelope(fixture.declaration, "gocode.rc0.qualified-declaration/1")
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_BINDING_MISMATCH"):
            verify_qualified_declaration(alternate_declaration, fixture.policy, fixture.mapping, fixture.resolver, fixture.verify_envelope, fixture.now_epoch_seconds)
        alternate_report = _alternate_schema_envelope(fixture.report, "gocode.rc0.schema.verification-report/3")
        with self.assertRaisesRegex(PolicyFailure, "REPORT_PROJECTION_MISMATCH"):
            validate_report_against_policy(alternate_report, fixture.mapping.rc0_trust_policy, fixture.mapping, fixture.now_epoch_seconds)
        with self.assertRaisesRegex(PolicyFailure, "REPORT_PROJECTION_MISMATCH"):
            verify_qualified_declaration(fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver, lambda _: fixture.declaration, fixture.now_epoch_seconds)

    def test_report_requires_all_required_gates_and_aggregates_to_pass(self) -> None:
        fixture = valid_declaration_fixture()
        def block(payload):
            payload["required_gate_results"][0].update(execution_outcome="FAIL", gate_result="BLOCKED", blocked_reason="REQUIRED_GATE_FAILED")
            payload["source_candidate_gate"] = {"gate_result": "BLOCKED", "blocked_reason": "REQUIRED_GATE_FAILED"}
            payload["overall_candidate_gate"] = {"gate_result": "BLOCKED", "blocked_reason": "REQUIRED_GATE_FAILED"}

        blocked = _resigned_report(fixture.report, block)
        with self.assertRaisesRegex(PolicyFailure, "REPORT_PROJECTION_MISMATCH"):
            validate_report_against_policy(blocked, fixture.mapping.rc0_trust_policy, fixture.mapping, fixture.now_epoch_seconds)

    def test_projection_uses_closed_gate_and_artifact_ordering_vectors(self) -> None:
        gates = [
            {"gate_id": "z-gate", "stage": "SOURCE_CANDIDATE", "execution_outcome": "PASS", "gate_result": "PASS", "binding": {"repository_id": "a"}},
            {"gate_id": "a-gate", "stage": "PRODUCTION_QUALIFICATION", "execution_outcome": "PASS", "gate_result": "PASS", "binding": {"repository_id": "z"}},
        ]
        ordered_gates = sorted(gates, key=lambda row: (row["gate_id"].encode(), row["stage"].encode(), canonical_bytes(row)))
        expected_gates = hashlib.sha256(b"gocode.rc0.required-gate-results-projection/1\0" + canonical_bytes(ordered_gates)).hexdigest()
        self.assertEqual(_projection({"required_gate_results": list(reversed(gates))}, False), expected_gates)
        artifacts = [
            {"relative_path": "z", "sha256": "a" * 64, "size": 1, "locator": "cas:sha256:" + "a" * 64},
            {"relative_path": "a", "sha256": "z" * 64, "size": 10, "locator": "cas:sha256:" + "z" * 64},
        ]
        ordered_artifacts = sorted(artifacts, key=lambda row: (row["relative_path"].encode(), row["sha256"].encode(), str(row["size"]).encode(), row["locator"].encode()))
        expected_artifacts = hashlib.sha256(b"gocode.rc0.exact-artifact-bindings-projection/1\0" + canonical_bytes(ordered_artifacts)).hexdigest()
        self.assertEqual(_projection({"exact_artifact_bindings": list(reversed(artifacts))}, True), expected_artifacts)

if __name__ == "__main__":
    unittest.main()
