"""Negative vectors for the fixture-only activation graph verifier."""

from __future__ import annotations

import unittest
import inspect
import copy
from dataclasses import replace

from scripts.rc0_policy.activation import ActivationFailure, ActivationView, VerifiedFloorWitness, fixture_verify_activation
from scripts.rc0_policy.canonical import loads_canonical
from scripts.rc0_policy.external_envelope import PrincipalBinding
from scripts.tests.rc0_platform_activation_support import (
    _envelope, _floor_bytes, _principals, alternate_activation_schema_envelope, floor_digest, reframed_envelope, replace_receipt_intent, timed_envelope, verify_fixture_floor, valid_active_fixture,
)


class ActivationTests(unittest.TestCase):
    def _verify(self, fixture, receipts=None, snapshot=None, **changes):
        return fixture_verify_activation(
            fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt) if receipts is None else receipts,
            fixture.snapshot if snapshot is None else snapshot, fixture.mapping, fixture.adjunct_trust,
            fixture.floor, changes.get("runner", fixture.runner_subject_id), changes.get("downstream", fixture.downstream_subject_id),
            changes.get("builds", fixture.expected_consumer_verifier_build_sha256s), fixture.now_epoch_seconds,
        )

    def test_two_receipts_bind_same_intent_not_snapshot(self) -> None:
        fixture = valid_active_fixture()
        wrong = replace_receipt_intent(fixture.downstream_receipt, fixture.snapshot.envelope_sha256)
        with self.assertRaisesRegex(ActivationFailure, "RECEIPT_INTENT_MISMATCH"):
            self._verify(fixture, (fixture.runner_receipt, wrong))

    def test_active_snapshot_requires_runner_and_downstream_receipts(self) -> None:
        fixture = valid_active_fixture()
        with self.assertRaisesRegex(ActivationFailure, "RECEIPT_SET_MISMATCH"):
            self._verify(fixture, (fixture.runner_receipt,))

    def test_revoke_snapshot_forbids_receipts_and_never_authorizes(self) -> None:
        fixture = valid_active_fixture()
        intent_payload = loads_canonical(fixture.intent.payload_canonical_bytes)
        intent_payload["activation_action"] = "revoke"
        intent = _envelope(intent_payload, "gocode.rc0.policy-activation-intent/1", "policy_authority", _principals()["policy_authority"])
        payload = loads_canonical(fixture.snapshot.payload_canonical_bytes)
        payload.update(activation_intent_envelope_sha256=intent.envelope_sha256, state="revoked", runner_acceptance_receipt_envelope_sha256=None, downstream_acceptance_receipt_envelope_sha256=None)
        revoked = _envelope(payload, "gocode.rc0.policy-activation-snapshot/1", "policy_authority", _principals()["policy_authority"])
        view = fixture_verify_activation(intent, (), revoked, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        self.assertEqual(view.state, "revoked")
        self.assertIsNone(view.runner_consumer_identity)
        self.assertIsNone(view.downstream_consumer_identity)

    def test_rejects_wrong_consumer_role_subject_or_verifier_build(self) -> None:
        fixture = valid_active_fixture()
        for changes in ({"runner": "wrong"}, {"builds": {"runner": "f" * 64, "downstream": "2" * 64}}):
            with self.subTest(changes=changes), self.assertRaises(ActivationFailure):
                self._verify(fixture, **changes)

    def test_rejects_intent_registry_envelope_or_payload_digest_mutation(self) -> None:
        fixture = valid_active_fixture()
        payload = loads_canonical(fixture.intent.payload_canonical_bytes)
        payload["adjunct_trust_registry_envelope_sha256"] = "f" * 64
        wrong = _envelope(payload, "gocode.rc0.policy-activation-intent/1", "policy_authority", _principals()["policy_authority"])
        with self.assertRaises(ActivationFailure):
            fixture_verify_activation(wrong, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)

    def test_rejects_intent_key_revocation_or_snapshot_authority_metadata_drift(self) -> None:
        fixture = valid_active_fixture()
        payload = loads_canonical(fixture.intent.payload_canonical_bytes)
        payload["revocation_epoch"] = 4
        wrong = _envelope(payload, "gocode.rc0.policy-activation-intent/1", "policy_authority", _principals()["policy_authority"])
        with self.assertRaisesRegex(ActivationFailure, "INTENT_INVALID"):
            fixture_verify_activation(wrong, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        object.__setattr__(fixture.snapshot, "issuer_key_id", "alternate-key")
        with self.assertRaises(ActivationFailure):
            self._verify(fixture)

    def test_fixture_floor_verifier_rejects_missing_corrupt_and_stale_witness(self) -> None:
        fixture = valid_active_fixture()
        with self.assertRaises(ValueError):
            verify_fixture_floor(None, fixture.mapping.envelope_sha256)
        with self.assertRaises(ValueError):
            verify_fixture_floor(b"{}", fixture.mapping.envelope_sha256)
        object.__setattr__(fixture.floor, "generation", 1)
        with self.assertRaisesRegex(ActivationFailure, "FLOOR_INVALID"):
            self._verify(fixture)

    def test_view_and_floor_direct_construction_replace_or_drift_reject(self) -> None:
        fixture = valid_active_fixture()
        view = self._verify(fixture)
        with self.assertRaises(TypeError):
            ActivationView(object())
        with self.assertRaises(TypeError):
            VerifiedFloorWitness(object())
        with self.assertRaises(TypeError):
            replace(view, state="revoked")
        with self.assertRaises(TypeError):
            replace(fixture.floor, generation=1)
        unowned = object.__new__(ActivationView)
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            unowned.require_verified(fixture.now_epoch_seconds)
        unowned_floor = object.__new__(VerifiedFloorWitness)
        with self.assertRaisesRegex(ActivationFailure, "FLOOR_INVALID"):
            fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, unowned_floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        object.__setattr__(view, "state", "revoked")
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)

    def test_view_replay_after_envelope_expiry_rejects(self) -> None:
        fixture = valid_active_fixture()
        view = self._verify(fixture)
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds + 11)

    def test_deadline_and_caller_container_mutation_fail_closed_or_replay_frozen(self) -> None:
        fixture = valid_active_fixture()
        payload = loads_canonical(fixture.intent.payload_canonical_bytes)
        payload["activation_deadline"] = "2023-11-14T22:13:21Z"
        expired = _envelope(payload, "gocode.rc0.policy-activation-intent/1", "policy_authority", _principals()["policy_authority"])
        with self.assertRaisesRegex(ActivationFailure, "INTENT_TIME_INVALID"):
            fixture_verify_activation(expired, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds + 2)
        receipts, builds = [fixture.runner_receipt, fixture.downstream_receipt], dict(fixture.expected_consumer_verifier_build_sha256s)
        view = fixture_verify_activation(fixture.intent, receipts, fixture.snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, builds, fixture.now_epoch_seconds)
        receipts.clear(); builds["runner"] = "f" * 64
        view.require_verified(fixture.now_epoch_seconds)

    def test_floor_identity_and_view_shape_are_exact(self) -> None:
        fixture = valid_active_fixture()
        clone = copy.copy(fixture.floor)
        with self.assertRaisesRegex(ActivationFailure, "FLOOR_INVALID"):
            fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, clone, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        self.assertEqual(tuple(ActivationView.__dataclass_fields__), ("activation_id", "activation_epoch", "mapping_policy_envelope_sha256", "adjunct_trust_registry_envelope_sha256", "adjunct_trust_registry_payload_sha256", "rc0_qualification_policy_digest", "snapshot_envelope_sha256", "policy_authority_identity", "runner_consumer_identity", "downstream_consumer_identity", "state", "_canonical_source_bytes", "_verification_token"))
        self.assertFalse(ActivationView.__dataclass_params__.eq)
        self.assertEqual(tuple(inspect.signature(ActivationView.require_verified).parameters), ("self", "now_epoch_seconds"))

    def test_all_registry_principals_and_current_floor_edges_remain_disjoint(self) -> None:
        fixture = valid_active_fixture(); policy = _principals()["policy_authority"]
        intent_payload = loads_canonical(fixture.intent.payload_canonical_bytes); intent_payload["runner_consumer_subject_id"] = policy["subject_id"]
        intent = _envelope(intent_payload, "gocode.rc0.policy-activation-intent/1", "policy_authority", policy)
        runner_payload = loads_canonical(fixture.runner_receipt.payload_canonical_bytes); runner_payload.update(activation_intent_envelope_sha256=intent.envelope_sha256, consumer_subject_id=policy["subject_id"])
        runner = _envelope(runner_payload, "gocode.rc0.policy-acceptance-receipt/1", "runner", policy)
        downstream_payload = loads_canonical(fixture.downstream_receipt.payload_canonical_bytes); downstream_payload["activation_intent_envelope_sha256"] = intent.envelope_sha256
        downstream = _envelope(downstream_payload, "gocode.rc0.policy-acceptance-receipt/1", "downstream", {
            "subject_id": fixture.downstream_receipt.issuer_subject_id, "controlling_account_id": fixture.downstream_receipt.issuer_controlling_account_id, "delegated_session_id": fixture.downstream_receipt.issuer_delegated_session_id, "lane_id": fixture.downstream_receipt.issuer_lane_id,
        })
        snapshot_payload = loads_canonical(fixture.snapshot.payload_canonical_bytes); snapshot_payload.update(activation_intent_envelope_sha256=intent.envelope_sha256, runner_acceptance_receipt_envelope_sha256=runner.envelope_sha256, downstream_acceptance_receipt_envelope_sha256=downstream.envelope_sha256)
        snapshot = _envelope(snapshot_payload, "gocode.rc0.policy-activation-snapshot/1", "policy_authority", policy)
        with self.assertRaisesRegex(ActivationFailure, "PRINCIPAL_OVERLAP"):
            fixture_verify_activation(intent, (runner, downstream), snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, policy["subject_id"], fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        genesis = {"repository_id": "gocode", "generation": 0, "state": "genesis", "activation_epoch": 0, "snapshot_envelope_sha256": None, "predecessor_snapshot_envelope_sha256": None}
        current_raw = {"repository_id": "gocode", "generation": 1, "state": "current", "activation_epoch": 1, "snapshot_envelope_sha256": "a" * 64, "predecessor_snapshot_envelope_sha256": None}
        verify_fixture_floor(_floor_bytes(genesis, floor_digest(genesis)), floor_digest(genesis))
        current = verify_fixture_floor(_floor_bytes(current_raw, floor_digest(current_raw)), floor_digest(current_raw))
        with self.assertRaisesRegex(ActivationFailure, "FLOOR_LINEAGE_MISMATCH"):
            fixture_verify_activation(fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot, fixture.mapping, fixture.adjunct_trust, current, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)
        view = self._verify(valid_active_fixture())
        object.__setattr__(view, "_canonical_source_bytes", b"changed")
        with self.assertRaisesRegex(ActivationFailure, "ACTIVATION_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)

    def test_receipt_and_snapshot_payload_times_equal_signed_issued_at(self) -> None:
        fixture = valid_active_fixture()
        receipt_payload = loads_canonical(fixture.runner_receipt.payload_canonical_bytes)
        receipt_payload["accepted_at"] = "2023-11-14T22:13:19Z"
        wrong_receipt = _envelope(receipt_payload, "gocode.rc0.policy-acceptance-receipt/1", "runner", {
            "subject_id": fixture.runner_receipt.issuer_subject_id, "controlling_account_id": fixture.runner_receipt.issuer_controlling_account_id,
            "delegated_session_id": fixture.runner_receipt.issuer_delegated_session_id, "lane_id": fixture.runner_receipt.issuer_lane_id,
        })
        with self.assertRaisesRegex(ActivationFailure, "RECEIPT_TIME_INVALID"):
            self._verify(fixture, (wrong_receipt, fixture.downstream_receipt))
        snapshot_payload = loads_canonical(fixture.snapshot.payload_canonical_bytes)
        snapshot_payload["activated_at"] = "2023-11-14T22:13:19Z"
        wrong_snapshot = _envelope(snapshot_payload, "gocode.rc0.policy-activation-snapshot/1", "policy_authority", _principals()["policy_authority"])
        with self.assertRaisesRegex(ActivationFailure, "INTENT_TIME_INVALID"):
            self._verify(fixture, snapshot=wrong_snapshot)

    def test_microsecond_receipt_after_snapshot_same_second_rejects(self) -> None:
        fixture = valid_active_fixture(); policy = _principals()["policy_authority"]; now = fixture.now_epoch_seconds + 1
        intent_payload = loads_canonical(fixture.intent.payload_canonical_bytes); intent_payload["activation_deadline"] = "2023-11-14T22:13:30.000000Z"
        intent = timed_envelope(intent_payload, "gocode.rc0.policy-activation-intent/1", "policy_authority", policy, "2023-11-14T22:13:19.000000Z", now)
        receipt_payloads = []
        for receipt in (fixture.runner_receipt, fixture.downstream_receipt):
            payload = loads_canonical(receipt.payload_canonical_bytes); payload.update(activation_intent_envelope_sha256=intent.envelope_sha256, accepted_at="2023-11-14T22:13:20.900000Z")
            principal = {"subject_id": receipt.issuer_subject_id, "controlling_account_id": receipt.issuer_controlling_account_id, "delegated_session_id": receipt.issuer_delegated_session_id, "lane_id": receipt.issuer_lane_id}
            receipt_payloads.append(timed_envelope(payload, "gocode.rc0.policy-acceptance-receipt/1", receipt.issuer_role, principal, "2023-11-14T22:13:20.900000Z", now))
        snapshot_payload = loads_canonical(fixture.snapshot.payload_canonical_bytes); snapshot_payload.update(activation_intent_envelope_sha256=intent.envelope_sha256, runner_acceptance_receipt_envelope_sha256=receipt_payloads[0].envelope_sha256, downstream_acceptance_receipt_envelope_sha256=receipt_payloads[1].envelope_sha256, activated_at="2023-11-14T22:13:20.100000Z")
        snapshot = timed_envelope(snapshot_payload, "gocode.rc0.policy-activation-snapshot/1", "policy_authority", policy, "2023-11-14T22:13:20.100000Z", now)
        with self.assertRaisesRegex(ActivationFailure, "RECEIPT_TIME_INVALID"):
            fixture_verify_activation(intent, tuple(receipt_payloads), snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, now)

    def test_same_id_alternate_activation_schema_with_extra_field_rejects(self) -> None:
        fixture = valid_active_fixture()
        vectors = ((alternate_activation_schema_envelope(fixture.intent, fixture.now_epoch_seconds), (fixture.runner_receipt, fixture.downstream_receipt), fixture.snapshot), (fixture.intent, (alternate_activation_schema_envelope(fixture.runner_receipt, fixture.now_epoch_seconds), fixture.downstream_receipt), fixture.snapshot), (fixture.intent, (fixture.runner_receipt, fixture.downstream_receipt), alternate_activation_schema_envelope(fixture.snapshot, fixture.now_epoch_seconds)))
        for intent, receipts, snapshot in vectors:
            with self.subTest(schema=intent.payload_schema_id), self.assertRaisesRegex(ActivationFailure, "ENVELOPE_INVALID"):
                fixture_verify_activation(intent, receipts, snapshot, fixture.mapping, fixture.adjunct_trust, fixture.floor, fixture.runner_subject_id, fixture.downstream_subject_id, fixture.expected_consumer_verifier_build_sha256s, fixture.now_epoch_seconds)

    def test_every_policy_authority_key_tuple_component_rejects(self) -> None:
        changes = {
            "issuer": {"issuer": "OTHER", "signature_profile_id": "OTHER"},
            "issuer_key_id": {"issuer_key_id": "other-key"}, "issuer_key_epoch": {"issuer_key_epoch": 8},
            "issuer_revocation_epoch": {"issuer_revocation_epoch": 4},
            "signature_profile_id": {"issuer": "OTHER", "signature_profile_id": "OTHER"},
        }
        for field, replacement in changes.items():
            fixture = valid_active_fixture()
            snapshot = reframed_envelope(fixture.snapshot, fixture.now_epoch_seconds, **replacement)
            with self.subTest(field=field), self.assertRaises(ActivationFailure):
                self._verify(fixture, snapshot=snapshot)

    def test_floor_sealer_is_stateless_content_bound_and_identity_safe(self) -> None:
        genesis = {"repository_id": "gocode", "generation": 0, "state": "genesis", "activation_epoch": 0, "snapshot_envelope_sha256": None, "predecessor_snapshot_envelope_sha256": None}
        first = {"repository_id": "gocode", "generation": 1, "state": "current", "activation_epoch": 1, "snapshot_envelope_sha256": "1" * 64, "predecessor_snapshot_envelope_sha256": None}
        second = {"repository_id": "gocode", "generation": 2, "state": "current", "activation_epoch": 2, "snapshot_envelope_sha256": "2" * 64, "predecessor_snapshot_envelope_sha256": "1" * 64}
        old_digest, first_digest, second_digest = map(floor_digest, (genesis, first, second))
        old = verify_fixture_floor(_floor_bytes(genesis, old_digest), old_digest)
        self.assertIsNot(old, verify_fixture_floor(_floor_bytes(genesis, old_digest), old_digest))
        sibling = verify_fixture_floor(_floor_bytes(first, first_digest), first_digest)
        successor = verify_fixture_floor(_floor_bytes(second, second_digest), second_digest)
        self.assertEqual((sibling.generation, successor.activation_epoch), (1, 2))
        self.assertEqual(old.generation, 0)
        with self.assertRaises(ValueError):
            verify_fixture_floor(_floor_bytes(genesis, old_digest), "c" * 64)
        with self.assertRaises(ValueError):
            verify_fixture_floor(_floor_bytes(genesis, "c" * 64), "c" * 64)
        for malformed in ({**first, "predecessor_snapshot_envelope_sha256": "0" * 64}, {**second, "snapshot_envelope_sha256": "1" * 64}):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                _floor_bytes(malformed, "c" * 64)

    def test_valid_active_fixture_retains_signed_full_principals(self) -> None:
        fixture = valid_active_fixture()
        view = self._verify(fixture)
        principal = _principals()["policy_authority"]
        self.assertEqual(view.policy_authority_identity, PrincipalBinding("policy_authority", **principal))
        self.assertEqual(view.runner_consumer_identity.subject_id, fixture.runner_subject_id)
        self.assertEqual(view.downstream_consumer_identity.subject_id, fixture.downstream_subject_id)


if __name__ == "__main__":
    unittest.main()
