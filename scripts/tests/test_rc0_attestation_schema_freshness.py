"""Freshness contract regression tests for the outer platform attestation."""

from __future__ import annotations

import hashlib
import unittest
from copy import deepcopy
from pathlib import Path

from scripts.rc0_policy.adjunct_schema_validation import (
    parse_adjunct_schema,
    validate_adjunct_schema_instance,
)
from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.tests.rc0_platform_envelope_support import _schema_documents


_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_ID = "gocode.rc0.platform-scope-attestation/1"
_SCHEMA_PATH = _ROOT / "docs/schemas/rc0-platform-scope-attestation-v1.schema.json"
_REGISTRY_PATH = _ROOT / "scripts/rc0_policy/fixtures/platform_scope/v1/valid/fixture-adjunct-trust-schema-registry-v1.json"
_SHA = "a" * 64
_EXPECTED_DIGESTS = {
    "gocode.external-signed-envelope/1": "5eba8ce2e72712b724c4a5d696ef221ce83638284cabe997fac8765563cc85a6",
    "gocode.governance.platform-decision-acceptance/1": "96cf0b500803ff0504af73507f02265a7896442ba792a5b0f455fa111f2b0910",
    "gocode.rc0.artifact-measurement-record/1": "f65252ba672442b879088fc34dbe8879c6dfa20b981f102dc7e8f0ba9dfd8d9e",
    "gocode.rc0.canary-evidence-record/1": "4bf837cf8881ec4b36c1b7c74135665022b10d928b405ee360aff189a0939d5f",
    "gocode.rc0.native-host-evidence-record/1": "d6ffc1561158e3dc082ac22004325539d7b5abb4ddba1a4cf0ce4109cdc9c41c",
    "gocode.rc0.platform-qualified-subject/1": "859f1b2474ae0e034917fade862078b827b9ec71f0a014df387c4b2644719186",
    "gocode.rc0.platform-scope-attestation/1": "abb309a10eee66afb4ab7e8df01bdbd378bcbe5fa4aaaf43982f0c890d4f1052",
    "gocode.rc0.platform-scope-mapping-policy/1": "6ed45371597db712121d353c3734ac38844b80ec4cfa25a950bf64972603c333",
    "gocode.rc0.policy-acceptance-receipt/1": "b513dc4b841bc7f46af14bab1bd49e61cf66dc23f0e7610bbf343c663f2a5176",
    "gocode.rc0.policy-activation-intent/1": "f691c4d47d5406bd160c916fedb284adf0b6eb066d0f762553ff0840862c132c",
    "gocode.rc0.policy-activation-snapshot/1": "f2d316a5f987be3ce6bd3212b023238a06b1fbb6eb10ad070cb9432c82566c08",
    "gocode.rc0.post-rc0-owner-authority-receipt/1": "91070df0d96c899d6f57b80327360932d27dbfa2aee58d779829f79959ddb96e",
    "gocode.rc0.post-rc0-platform-composed-universe/1": "c64164ee430e316affd9781a47a450f147f406cb09f2bdf31e14f333045dd8de",
    "gocode.rc0.post-rc0-reconciliation-receipt/1": "923d55f5164492ec724593f8badf2941ce43e3683eb719fbab0aac65782f4cff",
    "gocode.rc0.profile-evidence-record/1": "0aad4327d6a6ae0cb81288d8d20de946ebff1db076ac5a4c51a34ebe0b54cd8e",
    "gocode.rc0.qualified-declaration/1": "b4126dd4ab9b57cd21147e58d09fd84ebeaefc5ba4e60cd38b9a9081727b67ce",
    "gocode.release.platform-qualification-matrix/2": "6cabf7e5f81e72b74b67c829392f872f9ef07e9193db22bf0cf4798115cfb4db",
    "gocode.v1-platform-scope-claim-migration/1": "bc6cdc1861fe39e4be0ec118672a333a7d6994649d15f43b13611f8d35dd8285",
}


def _schema() -> dict[str, object]:
    return parse_adjunct_schema(_SCHEMA_PATH.read_bytes(), _SCHEMA_ID)


def _attestation() -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_ID, "repository_id": "gocode",
        "mapping_policy_envelope_sha256": _SHA, "adjunct_trust_registry_envelope_sha256": _SHA,
        "adjunct_trust_registry_payload_sha256": _SHA, "rc0_qualification_policy_digest": _SHA,
        "active_activation_snapshot_envelope_sha256": _SHA,
        "common_binding_group": {"repository_id": "gocode", "candidate_source_sha": "b" * 40,
            "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
            "observed_evidence_revision": "c" * 40, "evidence_bundle_digest": _SHA,
            "policy_revision": 3, "policy_digest": _SHA, "profile": "gocode.rc0.evidence-profile/3",
            "exact_artifact_bindings": [{"relative_path": "artifact", "sha256": _SHA,
                "size": 0, "locator": "cas:sha256:" + _SHA}]},
        "common_binding_group_payload_sha256": _SHA,
        "platform_scope_id": "linux-ubuntu-24_04-x86_64-production",
        "qualification_class": "production", "artifact_measurements": [_SHA, "b" * 64],
        "host_evidence_records": [_SHA], "profile_evidence_records": [_SHA],
        "canary_evidence_records": [], "observed_at": "2023-11-14T22:13:20Z",
        "freshness_deadline": "2023-11-14T22:13:30Z", "producing_lane_id": "aggregate",
    }


class AttestationSchemaFreshnessTests(unittest.TestCase):
    def test_accepts_second_and_microsecond_timestamp_forms(self) -> None:
        for observed_at, freshness_deadline in (
            ("2023-11-14T22:13:20Z", "2023-11-14T22:13:30Z"),
            ("2023-11-14T22:13:20.123456Z", "2023-11-14T22:13:30.123456Z"),
        ):
            with self.subTest(observed_at=observed_at):
                payload = _attestation()
                payload.update(observed_at=observed_at, freshness_deadline=freshness_deadline)
                self.assertEqual(validate_adjunct_schema_instance(_schema(), payload), ())

    def test_requires_exact_timestamp_text_but_defers_order_to_verifier(self) -> None:
        for field in ("observed_at", "freshness_deadline"):
            missing = _attestation(); del missing[field]
            trailing_newline = _attestation(); trailing_newline[field] += "\n"
            with self.subTest(field=field, mutation="missing"):
                self.assertTrue(validate_adjunct_schema_instance(_schema(), missing))
            with self.subTest(field=field, mutation="trailing_newline"):
                self.assertTrue(validate_adjunct_schema_instance(_schema(), trailing_newline))
        inverted = _attestation()
        inverted.update(observed_at="2023-11-14T22:13:30Z", freshness_deadline="2023-11-14T22:13:20Z")
        self.assertEqual(validate_adjunct_schema_instance(_schema(), inverted), ())

    def test_registry_has_exact_six_refreshed_pins_and_preserves_inventory(self) -> None:
        raw = _REGISTRY_PATH.read_bytes()
        payload = loads_canonical(raw)
        self.assertEqual(raw, canonical_bytes(payload) + b"\n")
        rows = payload["adjunct_schema_digests"]
        self.assertIsInstance(rows, list)
        pairs = tuple((row["schema_id"], row["schema_sha256"]) for row in rows)
        self.assertEqual(len(pairs), 18)
        self.assertEqual(pairs, tuple(sorted(pairs)))
        actual = dict(pairs)
        self.assertEqual(actual, _EXPECTED_DIGESTS)
        self.assertEqual(actual[_SCHEMA_ID], hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest())
        documents = _schema_documents()
        for schema_id, digest in actual.items():
            with self.subTest(schema_id=schema_id):
                self.assertEqual(digest, hashlib.sha256(documents[schema_id]).hexdigest())
