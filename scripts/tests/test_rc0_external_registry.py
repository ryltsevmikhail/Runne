"""External JSONL registry adapter and adjunct-registry boundary tests."""

from __future__ import annotations

import hashlib
import unittest
from copy import deepcopy

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.adjunct_registry import (
    AdjunctRegistryFailure, VerifiedAdjunctTrustRegistry, verify_adjunct_trust_registry,
)
from scripts.rc0_policy.external_envelope import canonical_lf, verify_signed_envelope
from scripts.rc0_policy.external_registry import parse_external_registry_jsonl
from scripts.tests.rc0_platform_envelope_support import (
    _NOW, _fixture_registry_payload, _fixture_schema_store,
    _schema_digest, _schema_documents, _signed_fixture_envelope, valid_fixture_envelope,
)


class EqualLooking:
    def __eq__(self, other: object) -> bool: return True
    def __ne__(self, other: object) -> bool: return False


def envelope_line(role: str) -> bytes:
    from scripts.rc0_policy.canonical import loads_canonical

    raw, _ = valid_fixture_envelope()
    envelope = loads_canonical(raw)
    envelope["issuer_role"] = role
    return canonical_lf(envelope)


class ExternalRegistryTests(unittest.TestCase):
    def registry_view(self, payload: object | None = None, domain: str = "FIXTURE_ONLY"):
        raw, verifier = valid_fixture_envelope()
        raw = _signed_fixture_envelope(_fixture_registry_payload() if payload is None else payload)
        envelope = verify_signed_envelope(raw, _fixture_schema_store(), verifier, _NOW)
        return verify_adjunct_trust_registry(envelope, _fixture_schema_store(), domain, _NOW)

    def assert_registry_failure(self, payload: object, code: str) -> None:
        with self.assertRaises(AdjunctRegistryFailure) as raised:
            self.registry_view(payload)
        self.assertEqual(raised.exception.code, code)

    def test_registry_view_is_verifier_owned(self) -> None:
        with self.assertRaises(TypeError):
            VerifiedAdjunctTrustRegistry()

    def test_registry_view_is_slotted_and_rejects_method_shadowing(self) -> None:
        view = self.registry_view()
        self.assertFalse(hasattr(view, "__dict__"))
        with self.assertRaises((AttributeError, TypeError)):
            view.require_verified = lambda now: None
        view.require_verified(_NOW)

    def test_returns_only_sorted_unique_canonical_lf_entries(self) -> None:
        first = envelope_line("A")
        second = envelope_line("B")
        lines = tuple(sorted((first, second), key=lambda line: hashlib.sha256(line[:-1]).hexdigest()))
        entries = parse_external_registry_jsonl(b"".join(lines))
        self.assertEqual(tuple(entry.envelope_sha256 for entry in entries), tuple(sorted((
            hashlib.sha256(first[:-1]).hexdigest(), hashlib.sha256(second[:-1]).hexdigest(),
        ))))
        self.assertEqual(tuple(entry.canonical_lf_bytes for entry in entries), lines)

    def test_rejects_missing_lf_crlf_blank_duplicate_and_noncanonical_records(self) -> None:
        line = envelope_line("A")
        other = envelope_line("B")
        unsorted = b"".join(reversed(sorted((line, other), key=lambda item: hashlib.sha256(item[:-1]).hexdigest())))
        vectors = (
            line[:-1], line.replace(b"\n", b"\r\n"), line + b"\n", line + line,
            b" " + canonical_bytes(_fixture_registry_payload()) + b"\n", unsorted,
        )
        for raw in vectors:
            with self.subTest(raw=raw[:16]):
                with self.assertRaises(ValueError):
                    parse_external_registry_jsonl(raw)

    def test_fixture_registry_pins_actual_full_adjunct_schema_set_and_validates_pairs(self) -> None:
        payload = _fixture_registry_payload()
        view = self.registry_view(payload)
        documents = _schema_documents()
        self.assertEqual(len(documents), 19)
        self.assertEqual(view.verification_domain, "FIXTURE_ONLY")
        self.assertEqual(view.adjunct_schema_digests, tuple(sorted(
            (schema_id, hashlib.sha256(raw).hexdigest())
            for schema_id, raw in documents.items()
            if schema_id != "gocode.rc0.post-rc0-adjunct-trust-schema-registry/1"
        )))
        self.assertEqual(tuple(role for role, _ in view.role_principal_constraints), (
            "POST_RC0_ADJUNCT_REGISTRY_AUTHORITY", "POST_RC0_G1_RECEIPT_AUTHORITY",
            "POST_RC0_RECONCILIATION_AUTHORITY", "artifact_classifier_a", "artifact_classifier_b",
            "desktop_platform_owner", "external_canary_operator", "mapping_policy_authority",
            "native_host_attestor", "policy_authority", "qualification_aggregator",
            "rc0_qualification_declarer", "rc0_qualification_reporter", "runtime_platform_owner",
        ))
        self.assertEqual(view.role_principal_constraints[-1][1].role_id, "runtime_platform_owner")
        from scripts.rc0_policy.canonical import loads_canonical
        from pathlib import Path

        root = Path(__file__).resolve().parents[2] / "scripts/rc0_policy/fixtures/platform_scope/v1/valid"
        for filename, schema_id in (
            ("fixture-composed-document-universe-v1.json", "gocode.rc0.post-rc0-platform-composed-universe/1"),
            ("fixture-claim-migration-v1.json", "gocode.v1-platform-scope-claim-migration/1"),
        ):
            _fixture_schema_store().validate(schema_id, _schema_digest(schema_id), loads_canonical((root / filename).read_bytes()))

    def test_task_three_fixture_set_keeps_document_and_composed_names_distinct(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[2] / "scripts/rc0_policy/fixtures/platform_scope/v1/valid"
        expected = {
            "fixture-adjunct-trust-schema-registry-v1.json",
            "fixture-base-document-universe-v1.json",
            "fixture-claim-migration-v1.json",
            "fixture-classified-delta-v1.json",
            "fixture-composed-document-universe-v1.json",
            "fixture-document-universe-v1.json",
            "fixture-rc0-qualification-policy-v1.json",
        }
        self.assertEqual({path.name for path in root.glob("*.json")}, expected)

    def test_registry_rejects_schema_set_digest_order_and_role_constraint_mutations(self) -> None:
        payload = _fixture_registry_payload()
        schema_set = deepcopy(payload)
        schema_set["adjunct_schema_digests"][0]["schema_id"] = schema_set["adjunct_schema_digests"][1]["schema_id"]
        digest = deepcopy(payload)
        digest["adjunct_schema_digests"][0]["schema_sha256"] = "0" * 64
        order = deepcopy(payload)
        order["adjunct_schema_digests"].reverse()
        role = deepcopy(payload)
        role["role_principal_constraints"][0]["role_id"] = role["role_principal_constraints"][1]["role_id"]
        for changed, code in ((schema_set, "REGISTRY_SCHEMA_SET_INVALID"), (digest, "REGISTRY_SCHEMA_SET_INVALID"), (order, "REGISTRY_SCHEMA_SET_INVALID"), (role, "REGISTRY_ROLE_CONSTRAINTS_INVALID")):
            with self.subTest(code=code):
                self.assert_registry_failure(changed, code)

    def test_registry_rejects_domain_mismatch_and_authority_overlap(self) -> None:
        with self.assertRaises(AdjunctRegistryFailure) as raised:
            self.registry_view(domain="PRODUCTION")
        self.assertEqual(raised.exception.code, "REGISTRY_DOMAIN_MISMATCH")
        overlap = _fixture_registry_payload()
        overlap["role_principal_constraints"][1]["principal"] = deepcopy(overlap["role_principal_constraints"][0]["principal"])
        self.assert_registry_failure(overlap, "REGISTRY_PRINCIPAL_OVERLAP")

    def test_registry_rejects_operational_identity_component_overlap(self) -> None:
        overlap = _fixture_registry_payload()
        overlap["role_principal_constraints"][3]["principal"]["lane_id"] = "registry-lane"
        self.assert_registry_failure(overlap, "REGISTRY_PRINCIPAL_OVERLAP")

    def test_registry_revalidates_opaque_bytes_and_time_before_use(self) -> None:
        view = self.registry_view()
        view.require_verified(_NOW)
        with self.assertRaises(AdjunctRegistryFailure) as raised:
            view.require_verified(view.expires_at_epoch_seconds + 1)
        self.assertEqual(raised.exception.code, "REGISTRY_VERIFIED_INVALID")
        object.__setattr__(view, "payload_sha256", "0" * 64)
        with self.assertRaises(AdjunctRegistryFailure) as raised:
            view.require_verified(_NOW)
        self.assertEqual(raised.exception.code, "REGISTRY_VERIFIED_INVALID")

    def test_registry_replay_rejects_reframed_signed_envelope_source(self) -> None:
        view = self.registry_view()
        envelope = loads_canonical(view.envelope_canonical_bytes)
        envelope["signature"] = "0" * 64
        source = canonical_bytes(envelope)
        object.__setattr__(view, "envelope_canonical_bytes", source)
        object.__setattr__(view, "envelope_sha256", hashlib.sha256(source).hexdigest())
        with self.assertRaises(AdjunctRegistryFailure) as raised:
            view.require_verified(_NOW)
        self.assertEqual(raised.exception.code, "REGISTRY_VERIFIED_INVALID")

    def test_registry_replay_rejects_equal_looking_retained_values(self) -> None:
        for field in ("registry_authority", "payload_sha256", "adjunct_schema_digests"):
            view = self.registry_view()
            object.__setattr__(view, field, EqualLooking())
            with self.subTest(field=field):
                with self.assertRaises(AdjunctRegistryFailure) as raised:
                    view.require_verified(_NOW)
                self.assertEqual(raised.exception.code, "REGISTRY_VERIFIED_INVALID")

    def test_registry_rejects_every_authority_shortcut_drift(self) -> None:
        view = self.registry_view()
        for field in ("registry_authority", "receipt_authority", "reconciliation_authority"):
            original = getattr(view, field)
            object.__setattr__(view, field, object())
            with self.subTest(field=field):
                with self.assertRaises(AdjunctRegistryFailure) as raised:
                    view.require_verified(_NOW)
                self.assertEqual(raised.exception.code, "REGISTRY_VERIFIED_INVALID")
            object.__setattr__(view, field, original)


if __name__ == "__main__":
    unittest.main()
