"""Fixture-only exact RC0 mapping-policy tests."""

import dataclasses
import hashlib
import weakref
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.rc0_policy.platform_policy import PolicyFailure, fixture_verify_mapping_policy
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import EnvelopeFailure
from scripts.tests.rc0_platform_policy_support import (
    _envelope, _host_pins, _principals, add_unknown_gate, change_profile_state, change_scope_slot_revision_or_null,
    mix_rc0_policy_digest, remove_required_gate, valid_mapping_fixture,
)


class _OriginalLookingRow:
    """A row impostor that fingerprints like the original but reads differently."""

    __slots__ = ("_original",)

    def __init__(self, original: object) -> None:
        self._original = original

    @property
    def __dict__(self) -> dict[str, object]:
        return self._original.__dict__

    def __getattr__(self, name: str) -> str:
        return f"substituted-{name}"

    def __eq__(self, other: object) -> bool:
        return True


class _RegistryProxy:
    """Delegates attributes while not being the verifier-minted registry."""

    def __init__(self, registry: object) -> None:
        self._registry = registry

    def __getattr__(self, name: str) -> object:
        return getattr(self._registry, name)


class MappingPolicyTests(unittest.TestCase):
    def test_rejects_added_removed_unknown_or_cross_policy_gate(self) -> None:
        fixture = valid_mapping_fixture()
        for mutation in (add_unknown_gate, remove_required_gate, mix_rc0_policy_digest):
            with self.subTest(mutation=mutation.__name__), self.assertRaisesRegex(PolicyFailure, "RC0_MAPPING_SET_MISMATCH"):
                fixture_verify_mapping_policy(**mutation(fixture).arguments())

    def test_profile_state_matrix_matches_all_three_exact_scopes(self) -> None:
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        self.assertEqual(len(mapping.platform_scopes), 3)
        self.assertEqual(len(mapping.artifact_slots), 5)
        self.assertEqual(len(mapping.profile_states), 18)

    def test_host_identity_pins_are_exact_sorted_three_scope_mapping_rows(self) -> None:
        fixture = valid_mapping_fixture()
        mapping = fixture_verify_mapping_policy(**fixture.arguments())
        self.assertEqual(tuple(row.__dict__ for row in mapping.host_identity_pins), tuple(_host_pins()))
        vectors = {
            "missing": lambda rows: rows.pop(),
            "extra": lambda rows: rows.append({**rows[-1], "platform_scope_id": "linux-ubuntu-24_04-x86_64-production"}),
            "duplicate": lambda rows: rows.__setitem__(1, dict(rows[0])),
            "unsorted": lambda rows: rows.reverse(),
            "cross_scope": lambda rows: rows.__setitem__(0, {**rows[0], "platform_scope_id": rows[-1]["platform_scope_id"]}),
            "alias": lambda rows: rows.__setitem__(0, {**rows[0], "platform_scope_id": "ubuntu-24.04"}),
            "partial": lambda rows: rows[0].pop("backend_version"),
            "nonhex": lambda rows: rows.__setitem__(0, {**rows[0], "kernel_or_image_sha256": "g" * 64}),
            "unknown": lambda rows: rows[0].update(unexpected="value"),
        }
        for name, mutate in vectors.items():
            with self.subTest(name=name):
                payload = loads_canonical(fixture.envelope.payload_canonical_bytes)
                mutate(payload["host_identity_pins"])
                if name in {"missing", "extra", "duplicate", "alias", "partial", "nonhex", "unknown"}:
                    with self.assertRaises(EnvelopeFailure):
                        _envelope(payload, "gocode.rc0.platform-scope-mapping-policy/1", "mapping_policy_authority", _principals()["mapping_policy_authority"])
                else:
                    changed = _envelope(payload, "gocode.rc0.platform-scope-mapping-policy/1", "mapping_policy_authority", _principals()["mapping_policy_authority"])
                    with self.assertRaisesRegex(PolicyFailure, "RC0_MAPPING_SET_MISMATCH"):
                        fixture_verify_mapping_policy(**dataclasses.replace(fixture, envelope=changed).arguments())

    def test_profile_state_mutation_rejects_exact_matrix(self) -> None:
        with self.assertRaisesRegex(PolicyFailure, "RC0_MAPPING_SET_MISMATCH"):
            fixture_verify_mapping_policy(**change_profile_state(valid_mapping_fixture()).arguments())

    def test_registry_schema_and_role_views_are_frozen(self) -> None:
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        self.assertEqual(len(mapping.authority_roles), 14)
        self.assertEqual(len(mapping.adjunct_schema_digests), 18)
        with self.assertRaises(AttributeError):
            mapping.adjunct_schema_digests.append(("x", "y"))

    def test_rc0_trust_view_is_derived_not_mapping_authored(self) -> None:
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        self.assertEqual(mapping.rc0_trust_policy.canonical_sha256, __import__("hashlib").sha256(mapping.rc0_trust_policy.canonical_bytes).hexdigest())

    def test_replay_rejects_every_rc0_trust_view_field_mutation(self) -> None:
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        trust = mapping.rc0_trust_policy
        vectors = {"rc0_qualification_policy_digest": "f" * 64, "canonical_bytes": b"{}",
                   "canonical_sha256": "f" * 64, "schema_id_hash_pairs": (),
                   "required_gate_projection": (), "legacy_issuer_role_strings": ()}
        for field, changed in vectors.items():
            with self.subTest(field=field):
                original = getattr(trust, field)
                object.__setattr__(trust, field, changed)
                with self.assertRaisesRegex(PolicyFailure, "MAPPING_VERIFIED_INVALID"):
                    mapping.require_verified(1_700_000_000)
                object.__setattr__(trust, field, original)

    def test_mapping_view_direct_construction_replace_or_source_drift_rejects(self) -> None:
        from scripts.rc0_policy.platform_policy import VerifiedMappingPolicy
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        self.assertFalse(hasattr(mapping, "__dict__")); self.assertIs(weakref.ref(mapping)(), mapping)
        with self.assertRaises((AttributeError, TypeError)): object.__setattr__(mapping, "require_verified", lambda _: None)
        with self.assertRaises(TypeError):
            VerifiedMappingPolicy()
        with self.assertRaises(TypeError):
            dataclasses.replace(mapping, activation_epoch=2)
        original = mapping._canonical_source_bytes
        object.__setattr__(mapping, "_canonical_source_bytes", b"drift")
        with self.assertRaises(PolicyFailure):
            mapping.require_verified(1_700_000_000)
        object.__setattr__(mapping, "_canonical_source_bytes", original)

    def test_verified_view_rechecks_every_public_and_internal_binding(self) -> None:
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        vectors = {"activation_epoch": 2, "rc0_qualification_policy_digest": "f" * 64,
                   "platform_scopes": (), "host_identity_pins": (), "adjunct_schema_digests": ()}
        for field, changed in vectors.items():
            with self.subTest(field=field):
                original = getattr(mapping, field)
                object.__setattr__(mapping, field, changed)
                with self.assertRaisesRegex(PolicyFailure, "MAPPING_VERIFIED_INVALID"):
                    mapping.require_verified(1_700_000_000)
                object.__setattr__(mapping, field, original)

    def test_replay_rejects_original_looking_custom_row_substitution(self) -> None:
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        vectors = ("host_identity_pins", "platform_scopes")
        for field in vectors:
            with self.subTest(field=field):
                original = getattr(mapping, field)
                substituted = (_OriginalLookingRow(original[0]), *original[1:])
                object.__setattr__(mapping, field, substituted)
                with self.assertRaisesRegex(PolicyFailure, "MAPPING_VERIFIED_INVALID"):
                    mapping.require_verified(1_700_000_000)
                object.__setattr__(mapping, field, original)

    def test_replay_rejects_equal_looking_registry_substitution(self) -> None:
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        original = mapping.adjunct_trust
        object.__setattr__(mapping, "adjunct_trust", _RegistryProxy(original))
        with self.assertRaisesRegex(PolicyFailure, "MAPPING_VERIFIED_INVALID"):
            mapping.require_verified(1_700_000_000)
        object.__setattr__(mapping, "adjunct_trust", original)

    def test_lineage_and_matrix_one_field_mutations_reject(self) -> None:
        fixture = valid_mapping_fixture()
        for field in ("scope", "slot", "revision", "null"):
            with self.subTest(field=field), self.assertRaisesRegex(PolicyFailure, "RC0_MAPPING_SET_MISMATCH"):
                fixture_verify_mapping_policy(**change_scope_slot_revision_or_null(fixture, field).arguments())
        vectors = ("base_document_universe_raw", "classified_delta_raw", "composed_document_universe_raw", "claim_registry_raw")
        for field in vectors:
            with self.subTest(field=field):
                raw = getattr(fixture, field); value = loads_canonical(raw)
                if field == "claim_registry_raw": value["claims"][0]["expected_paths"] = ["docs/00-foundation/README.md"]
                elif field == "composed_document_universe_raw": value["base_paths"] = []
                else: value["rows"][0]["content_sha256"] = "f" * 64
                changed = dataclasses.replace(fixture, **{field: canonical_bytes(value)})
                with self.assertRaises(PolicyFailure):
                    fixture_verify_mapping_policy(**changed.arguments())

    def test_decision_and_schema_substitution_cannot_be_coordinated(self) -> None:
        fixture = valid_mapping_fixture(); altered = loads_canonical(fixture.shared_decision_raw)
        altered["unsupported_tuples"][0] = "other"; raw = canonical_bytes(altered)
        with self.assertRaisesRegex(PolicyFailure, "SHARED_DECISION_INVALID"):
            fixture_verify_mapping_policy(**dataclasses.replace(fixture, shared_decision_raw=raw).arguments())
        mapping_payload = loads_canonical(fixture.envelope.payload_canonical_bytes)
        mapping_payload["shared_decision_schema_sha256"] = hashlib.sha256(b"substituted").hexdigest()
        from scripts.tests.rc0_platform_policy_support import _envelope, _principals
        changed_mapping = _envelope(mapping_payload, "gocode.rc0.platform-scope-mapping-policy/1", "mapping_policy_authority", _principals()["mapping_policy_authority"])
        with self.assertRaisesRegex(PolicyFailure, "MAPPING_BINDING_MISMATCH"):
            fixture_verify_mapping_policy(**dataclasses.replace(fixture, envelope=changed_mapping).arguments())

    def test_exact_profile_source_byte_mutation_rejects(self) -> None:
        fixture = valid_mapping_fixture(); original = Path.read_bytes
        target = Path("docs/profiles/openai-responses-text-v1.json").resolve()
        def mutate(path: Path) -> bytes:
            raw = original(path)
            return raw + b" " if path.resolve() == target else raw
        with patch.object(Path, "read_bytes", autospec=True, side_effect=mutate):
            with self.assertRaisesRegex(PolicyFailure, "RC0_MAPPING_SET_MISMATCH"):
                fixture_verify_mapping_policy(**fixture.arguments())

    def test_mapping_replay_and_coordinated_view_mutation_reject(self) -> None:
        mapping = fixture_verify_mapping_policy(**valid_mapping_fixture().arguments())
        with self.assertRaisesRegex(PolicyFailure, "MAPPING_ENVELOPE_TIME_INVALID"):
            mapping.require_verified(1_700_000_011)
        outer = loads_canonical(mapping._canonical_source_bytes); outer["payload"]["activation_epoch"] = 2
        raw = canonical_bytes(outer); original = (mapping._canonical_source_bytes, mapping.envelope_sha256, mapping.activation_epoch)
        object.__setattr__(mapping, "_canonical_source_bytes", raw)
        object.__setattr__(mapping, "envelope_sha256", hashlib.sha256(raw).hexdigest())
        object.__setattr__(mapping, "activation_epoch", 2)
        with self.assertRaisesRegex(PolicyFailure, "MAPPING_VERIFIED_INVALID"):
            mapping.require_verified(1_700_000_000)
        for field, value in zip(("_canonical_source_bytes", "envelope_sha256", "activation_epoch"), original): object.__setattr__(mapping, field, value)

    def test_rows_reject_noncanonical_empty_or_nonhex_content(self) -> None:
        fixture = valid_mapping_fixture()
        vectors = (fixture.base_document_universe_raw + b"\n",)
        for raw in vectors:
            with self.assertRaisesRegex(PolicyFailure, "FIXTURE_LINEAGE_MISMATCH"):
                fixture_verify_mapping_policy(**dataclasses.replace(fixture, base_document_universe_raw=raw).arguments())
        for value in ("", "g" * 64):
            raw = loads_canonical(fixture.base_document_universe_raw); raw["rows"][0]["classification" if not value else "content_sha256"] = value
            with self.assertRaisesRegex(PolicyFailure, "FIXTURE_LINEAGE_MISMATCH"):
                fixture_verify_mapping_policy(**dataclasses.replace(fixture, base_document_universe_raw=canonical_bytes(raw)).arguments())

    def test_claim_and_composed_reject_leading_or_trailing_raw_bytes(self) -> None:
        fixture = valid_mapping_fixture()
        for field in ("claim_registry_raw", "composed_document_universe_raw"):
            original = getattr(fixture, field)
            for raw in (b" " + original, original + b"\n"):
                with self.subTest(field=field, raw=raw[:1]), self.assertRaisesRegex(PolicyFailure, "FIXTURE_LINEAGE_MISMATCH"):
                    fixture_verify_mapping_policy(**dataclasses.replace(fixture, **{field: raw}).arguments())

    def test_claim_rows_reject_duplicate_id_or_cross_row_path(self) -> None:
        fixture = valid_mapping_fixture(); original = loads_canonical(fixture.claim_registry_raw)
        duplicate_id = loads_canonical(fixture.claim_registry_raw); clone = dict(duplicate_id["claims"][0]); clone["reason"] = "A distinct but duplicate claim ID."
        duplicate_id["claims"].append(clone)
        duplicate_path = loads_canonical(fixture.claim_registry_raw); clone = dict(duplicate_path["claims"][0]); clone.update(claim_id="Z_PLATFORM_SCOPE_FIXTURE", reason="A distinct claim must not share a path.")
        duplicate_path["claims"].append(clone)
        for value in (duplicate_id, duplicate_path):
            with self.assertRaisesRegex(PolicyFailure, "FIXTURE_LINEAGE_MISMATCH"):
                fixture_verify_mapping_policy(**dataclasses.replace(fixture, claim_registry_raw=canonical_bytes(value)).arguments())
        self.assertEqual(original["claims"], loads_canonical(fixture.claim_registry_raw)["claims"])

    def test_mapping_arrays_reject_independent_reverse_order(self) -> None:
        fixture = valid_mapping_fixture()
        from scripts.tests.rc0_platform_policy_support import _envelope, _principals
        for field in ("platform_scopes", "artifact_slot_mappings", "profile_state_matrix"):
            payload = loads_canonical(fixture.envelope.payload_canonical_bytes); payload[field].reverse()
            changed = _envelope(payload, "gocode.rc0.platform-scope-mapping-policy/1", "mapping_policy_authority", _principals()["mapping_policy_authority"])
            with self.subTest(field=field), self.assertRaisesRegex(PolicyFailure, "RC0_MAPPING_SET_MISMATCH"):
                fixture_verify_mapping_policy(**dataclasses.replace(fixture, envelope=changed).arguments())

    def test_adr_embedded_decision_digest_blocks_coordinated_owner_reissue(self) -> None:
        fixture = valid_mapping_fixture(); old = fixture.runtime_adr_raw; bad = old.replace(b"b1dee8ce2d62cf48d4073cf9e56f262f0c75bfc34a91011119e04e43a7bd6225", b"f" * 64)
        from scripts.tests.rc0_platform_policy_support import _envelope, _principals
        owner = loads_canonical(fixture.owner_acceptances[0].payload_canonical_bytes)
        owner.update(adr_document_sha256=hashlib.sha256(bad).hexdigest(), shared_decision_payload_sha256="f" * 64)
        changed_owner = _envelope(owner, "gocode.governance.platform-decision-acceptance/1", "runtime_platform_owner", _principals()["runtime_platform_owner"])
        payload = loads_canonical(fixture.envelope.payload_canonical_bytes)
        payload.update(runtime_adr_document_sha256=hashlib.sha256(bad).hexdigest(), runtime_owner_acceptance_envelope_sha256=changed_owner.envelope_sha256)
        changed_mapping = _envelope(payload, "gocode.rc0.platform-scope-mapping-policy/1", "mapping_policy_authority", _principals()["mapping_policy_authority"])
        changed = dataclasses.replace(fixture, envelope=changed_mapping, runtime_adr_raw=bad, owner_acceptances=(changed_owner, fixture.owner_acceptances[1]))
        with self.assertRaisesRegex(PolicyFailure, "OWNER_ACCEPTANCE_MISMATCH"):
            fixture_verify_mapping_policy(**changed.arguments())


if __name__ == "__main__":
    unittest.main()
