"""Signed contract vectors for activation graph authority boundaries."""

from __future__ import annotations

import inspect
import unittest
import weakref
from pathlib import Path
from typing import get_type_hints

from scripts.rc0_policy.activation import ActivationFailure, ActivationView, _floor, fixture_verify_activation
from scripts.rc0_policy.adjunct_registry import verify_adjunct_trust_registry
from scripts.rc0_policy.canonical import loads_canonical
from scripts.rc0_policy.external_envelope import verify_signed_envelope
from scripts.rc0_policy.platform_policy import PolicyFailure, fixture_verify_mapping_policy
from scripts.rc0_policy.platform_policy_mapping import VerifiedMappingPolicy
from scripts.rc0_policy.adjunct_registry import VerifiedAdjunctTrustRegistry
from scripts.tests.rc0_platform_envelope_support import _fixture_schema_store, valid_fixture_envelope
from scripts.tests.rc0_platform_activation_support import _envelope, _floor_bytes, _principals, floor_digest, reframed_envelope, valid_active_fixture, verify_fixture_floor


class EqualLooking:
    def __eq__(self, other: object) -> bool: return True
    def __ne__(self, other: object) -> bool: return False


class ActivationContractTests(unittest.TestCase):
    def _epoch_two_graph(self):
        from scripts.tests.rc0_platform_policy_support import valid_mapping_fixture
        fixture, source = valid_active_fixture(), valid_mapping_fixture()
        mapping_payload = loads_canonical(source.envelope.payload_canonical_bytes)
        mapping_payload.update(activation_epoch=2, predecessor_mapping_policy_envelope_sha256=source.envelope.envelope_sha256)
        mapping_envelope = _envelope(mapping_payload, source.envelope.payload_schema_id, "mapping_policy_authority", _principals()["mapping_policy_authority"])
        mapping = fixture_verify_mapping_policy(**{**source.arguments(), "envelope": mapping_envelope, "adjunct_trust": fixture.adjunct_trust})
        policy = _principals()["policy_authority"]
        intent_payload = loads_canonical(fixture.intent.payload_canonical_bytes)
        intent_payload.update(mapping_policy_envelope_sha256=mapping.envelope_sha256, rc0_qualification_policy_digest=mapping.rc0_qualification_policy_digest, shared_decision_payload_sha256=mapping.shared_decision_payload_sha256, activation_epoch=2, predecessor_activation_snapshot_envelope_sha256=fixture.snapshot.envelope_sha256)
        intent = _envelope(intent_payload, fixture.intent.payload_schema_id, "policy_authority", policy)
        receipts = []
        for value in (fixture.runner_receipt, fixture.downstream_receipt):
            payload = loads_canonical(value.payload_canonical_bytes)
            payload.update(activation_intent_envelope_sha256=intent.envelope_sha256, accepted_mapping_policy_envelope_sha256=mapping.envelope_sha256, accepted_rc0_qualification_policy_digest=mapping.rc0_qualification_policy_digest)
            principal = {key: getattr(value, "issuer_" + key) for key in ("subject_id", "controlling_account_id", "delegated_session_id", "lane_id")}
            receipts.append(_envelope(payload, value.payload_schema_id, value.issuer_role, principal))
        snapshot_payload = loads_canonical(fixture.snapshot.payload_canonical_bytes)
        snapshot_payload.update(mapping_policy_envelope_sha256=mapping.envelope_sha256, rc0_qualification_policy_digest=mapping.rc0_qualification_policy_digest, activation_epoch=2, predecessor_activation_snapshot_envelope_sha256=fixture.snapshot.envelope_sha256, activation_intent_envelope_sha256=intent.envelope_sha256, runner_acceptance_receipt_envelope_sha256=receipts[0].envelope_sha256, downstream_acceptance_receipt_envelope_sha256=receipts[1].envelope_sha256)
        snapshot = _envelope(snapshot_payload, fixture.snapshot.payload_schema_id, "policy_authority", policy)
        projection = {"repository_id": "gocode", "generation": 1, "state": "current", "activation_epoch": 1, "snapshot_envelope_sha256": fixture.snapshot.envelope_sha256, "predecessor_snapshot_envelope_sha256": None}
        floor = verify_fixture_floor(_floor_bytes(projection, floor_digest(projection)), floor_digest(projection))
        return fixture, intent, tuple(receipts), snapshot, mapping, floor

    def test_public_epoch_successor_and_non_successor_floor_reject(self) -> None:
        fixture, intent, receipts, snapshot, mapping, floor = self._epoch_two_graph()
        view = fixture_verify_activation(intent, receipts, snapshot, mapping, fixture.adjunct_trust, floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        self.assertEqual((view.activation_epoch, view.state), (2, "active"))
        with self.assertRaisesRegex(ActivationFailure, "FLOOR_GENESIS_MISMATCH"):
            fixture_verify_activation(intent, receipts, snapshot, mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)

    def test_floor_immediate_aba_predicate_rejects_current_and_predecessor(self) -> None:
        # A public candidate cannot have either digest without a SHA-256 collision: its signed
        # epoch, predecessor and intent bindings differ. Exercise the exact predicate directly.
        projection = {"repository_id": "gocode", "generation": 2, "state": "current", "activation_epoch": 2, "snapshot_envelope_sha256": "2" * 64, "predecessor_snapshot_envelope_sha256": "1" * 64}
        floor = verify_fixture_floor(_floor_bytes(projection, floor_digest(projection)), floor_digest(projection))
        for candidate in ("2" * 64, "1" * 64):
            with self.subTest(candidate=candidate), self.assertRaisesRegex(ActivationFailure, "FLOOR_LINEAGE_MISMATCH"):
                _floor(floor, 3, "2" * 64, candidate)

    def _overlap_graph(self, fixture, role: str, component: str):
        runner = {
            "subject_id": fixture.runner_receipt.issuer_subject_id,
            "controlling_account_id": fixture.runner_receipt.issuer_controlling_account_id,
            "delegated_session_id": fixture.runner_receipt.issuer_delegated_session_id,
            "lane_id": fixture.runner_receipt.issuer_lane_id,
        }
        runner[component] = _principals()[role][component]
        policy = _principals()["policy_authority"]
        intent_payload = loads_canonical(fixture.intent.payload_canonical_bytes)
        intent_payload["runner_consumer_subject_id"] = runner["subject_id"]
        intent = _envelope(intent_payload, fixture.intent.payload_schema_id, "policy_authority", policy)
        receipt_payload = loads_canonical(fixture.runner_receipt.payload_canonical_bytes)
        receipt_payload.update(activation_intent_envelope_sha256=intent.envelope_sha256, consumer_subject_id=runner["subject_id"])
        receipt = _envelope(receipt_payload, fixture.runner_receipt.payload_schema_id, "runner", runner)
        downstream_payload = loads_canonical(fixture.downstream_receipt.payload_canonical_bytes)
        downstream_payload["activation_intent_envelope_sha256"] = intent.envelope_sha256
        downstream = _envelope(downstream_payload, fixture.downstream_receipt.payload_schema_id, "downstream", {
            "subject_id": fixture.downstream_receipt.issuer_subject_id,
            "controlling_account_id": fixture.downstream_receipt.issuer_controlling_account_id,
            "delegated_session_id": fixture.downstream_receipt.issuer_delegated_session_id,
            "lane_id": fixture.downstream_receipt.issuer_lane_id,
        })
        snapshot_payload = loads_canonical(fixture.snapshot.payload_canonical_bytes)
        snapshot_payload.update(activation_intent_envelope_sha256=intent.envelope_sha256, runner_acceptance_receipt_envelope_sha256=receipt.envelope_sha256, downstream_acceptance_receipt_envelope_sha256=downstream.envelope_sha256)
        return intent, receipt, downstream, _envelope(snapshot_payload, fixture.snapshot.payload_schema_id, "policy_authority", policy), runner["subject_id"]

    def test_every_registry_identity_component_overlaps_only_after_resigning(self) -> None:
        fixture = valid_active_fixture()
        for role in _principals():
            for component in ("subject_id", "controlling_account_id", "delegated_session_id", "lane_id"):
                intent, runner, downstream, snapshot, subject = self._overlap_graph(fixture, role, component)
                with self.subTest(role=role, component=component), self.assertRaisesRegex(ActivationFailure, "PRINCIPAL_OVERLAP"):
                    fixture_verify_activation(intent, (runner, downstream), snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, subject, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)

    def test_minted_view_rejects_coordinated_prerequisite_retarget(self) -> None:
        fixture = valid_active_fixture()
        view = fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        replacement = reframed_envelope(fixture.intent, fixture.now_epoch_seconds, issuer_key_id="retargeted-key")
        object.__setattr__(fixture.intent, "envelope_canonical_bytes", replacement.envelope_canonical_bytes)
        object.__setattr__(fixture.intent, "envelope_sha256", replacement.envelope_sha256)
        object.__setattr__(fixture.intent, "issuer_key_id", replacement.issuer_key_id)
        object.__setattr__(fixture.intent, "trust", replacement.trust)
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)

    def test_activation_view_dependency_contract_uses_exact_originals(self) -> None:
        fixture = valid_active_fixture()
        view = fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        self.assertEqual(tuple(inspect.signature(ActivationView.require_dependencies).parameters), ("self", "mapping", "adjunct_trust", "now_epoch_seconds"))
        signature = get_type_hints(ActivationView.require_dependencies)
        self.assertIs(signature["mapping"], VerifiedMappingPolicy)
        self.assertIs(signature["adjunct_trust"], VerifiedAdjunctTrustRegistry)
        self.assertIs(signature["now_epoch_seconds"], int)
        self.assertIs(signature["return"], type(None))
        view.require_dependencies(fixture.mapping, fixture.adjunct_trust, fixture.now_epoch_seconds)

        from scripts.tests.rc0_platform_policy_support import valid_mapping_fixture
        replacement_source = valid_mapping_fixture()
        replacement = fixture_verify_mapping_policy(**replacement_source.arguments())
        self.assertIsNot(replacement, fixture.mapping)
        self.assertIsNot(replacement_source.adjunct_trust, fixture.adjunct_trust)
        self.assertEqual(replacement._canonical_source_bytes, fixture.mapping._canonical_source_bytes)
        for mapping, registry in ((replacement, replacement_source.adjunct_trust), (fixture.mapping, replacement_source.adjunct_trust), (replacement, fixture.adjunct_trust)):
            with self.subTest(mapping_is_original=mapping is fixture.mapping, registry_is_original=registry is fixture.adjunct_trust), self.assertRaisesRegex(ActivationFailure, "ACTIVATION_DEPENDENCY_INVALID"):
                view.require_dependencies(mapping, registry, fixture.now_epoch_seconds)

    def test_activation_view_dependency_contract_replays_before_identity_check(self) -> None:
        fixture = valid_active_fixture()
        view = fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        for mapping, registry in ((object(), fixture.adjunct_trust), (fixture.mapping, object())):
            with self.subTest(dependency=type(mapping if mapping is not fixture.mapping else registry).__name__), self.assertRaisesRegex(ActivationFailure, "ACTIVATION_DEPENDENCY_INVALID"):
                view.require_dependencies(mapping, registry, fixture.now_epoch_seconds)
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            view.require_dependencies(fixture.mapping, fixture.adjunct_trust, fixture.now_epoch_seconds + 100)
        object.__setattr__(view, "activation_epoch", True)
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            view.require_dependencies(object(), fixture.adjunct_trust, fixture.now_epoch_seconds)

    def test_view_is_slotted_weak_referenceable_and_rejects_method_shadowing(self) -> None:
        fixture = valid_active_fixture()
        view = fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        self.assertFalse(hasattr(view, "__dict__"))
        self.assertIs(weakref.ref(view)(), view)
        with self.assertRaises((AttributeError, TypeError)):
            view.require_verified = lambda now: None
        view.require_verified(fixture.now_epoch_seconds)

    def test_rejects_dependencies_outside_exact_verified_classes(self) -> None:
        class PermissiveDependency:
            def require_verified(self, now_epoch_seconds: int) -> None: pass

        fixture = valid_active_fixture()
        for mapping, registry in ((PermissiveDependency(), fixture.adjunct_trust), (fixture.mapping, PermissiveDependency())):
            with self.subTest(dependency=type(mapping if mapping is not fixture.mapping else registry).__name__), self.assertRaisesRegex(ActivationFailure, "MAPPING_OR_REGISTRY_INVALID"):
                fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, mapping, registry, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)

    def test_rejects_separately_minted_equal_registry(self) -> None:
        fixture = valid_active_fixture()
        raw, verifier = valid_fixture_envelope()
        registry = verify_adjunct_trust_registry(verify_signed_envelope(raw, _fixture_schema_store(), verifier, fixture.now_epoch_seconds), _fixture_schema_store(), "FIXTURE_ONLY", fixture.now_epoch_seconds)
        self.assertIsNot(registry, fixture.adjunct_trust)
        self.assertEqual(registry.envelope_canonical_bytes, fixture.adjunct_trust.envelope_canonical_bytes)
        with self.assertRaisesRegex(ActivationFailure, "MAPPING_OR_REGISTRY_INVALID"):
            fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, registry, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)

    def test_minted_view_rejects_equal_looking_public_principal(self) -> None:
        fixture = valid_active_fixture()
        view = fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        object.__setattr__(view, "policy_authority_identity", EqualLooking())
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)

    def test_minted_view_rejects_boolean_activation_epoch(self) -> None:
        fixture = valid_active_fixture()
        view = fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        object.__setattr__(view, "activation_epoch", True)
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)

    def test_mapping_activation_epoch_mismatch_rejects(self) -> None:
        fixture = valid_active_fixture()
        object.__setattr__(fixture.mapping, "activation_epoch", 2)
        with self.assertRaises(ActivationFailure):
            fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)

    def test_proposed_adr_cannot_produce_activation_mapping(self) -> None:
        from scripts.tests.rc0_platform_policy_support import valid_mapping_fixture
        source = valid_mapping_fixture(); raw = Path("docs/adr/ADR-0027-v1-platform-scope.md").read_bytes()
        with self.assertRaises(PolicyFailure):
            fixture_verify_mapping_policy(**{**source.arguments(), "runtime_adr_raw": raw})


if __name__ == "__main__":
    unittest.main()
