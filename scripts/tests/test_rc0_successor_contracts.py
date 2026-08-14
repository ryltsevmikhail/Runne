"""Structural boundary tests for the solo-owner post-RC0 lineage."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.rc0_policy.successor_contracts import (
    SuccessorContractFailure,
    successor_schema_ids,
    validate_successor_lineage,
    validate_successor_payload,
)


_HASH = "a" * 64
_FIXTURES = Path(__file__).resolve().parents[1] / "rc0_policy/fixtures/successor_contracts/v2"


class SuccessorContractTests(unittest.TestCase):
    def test_redacted_successor_fixtures_validate_without_g1(self) -> None:
        paths = sorted(_FIXTURES.glob("*.json"))
        self.assertEqual([path.stem for path in paths], ["intent", "mapping", "matrix", "registry", "snapshot", "subject"])
        for path in paths:
            with self.subTest(path=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                validate_successor_payload(path.stem, payload)
    def test_successor_ids_are_new_and_closed(self) -> None:
        self.assertEqual(
            successor_schema_ids(),
            (
                "gocode.rc0.post-rc0-adjunct-trust-schema-registry/2",
                "gocode.rc0.platform-scope-mapping-policy/2",
                "gocode.rc0.policy-activation-intent/2",
                "gocode.rc0.policy-activation-snapshot/2",
                "gocode.rc0.platform-qualified-subject/2",
                "gocode.release.platform-qualification-matrix/3",
            ),
        )

    def test_mapping_requires_solo_receipt_not_a_g1_receipt(self) -> None:
        payload = {
            "schema_version": "gocode.rc0.platform-scope-mapping-policy/2",
            "repository_id": "gocode",
            "project_owner_authority_receipt_sha256": _HASH,
            "adjunct_trust_schema_registry_envelope_sha256": "d" * 64,
            "mapping_policy_envelope_sha256": "e" * 64,
            "runtime_adr_document_sha256": "b" * 64,
            "desktop_adr_document_sha256": "c" * 64,
            "activation_epoch": 1,
            "predecessor_mapping_policy_envelope_sha256": None,
        }
        validate_successor_payload("mapping", payload)
        payload["g1_authority_receipt_envelope_sha256"] = _HASH
        with self.assertRaisesRegex(SuccessorContractFailure, "SUCCESSOR_G1_FIELD_FORBIDDEN"):
            validate_successor_payload("mapping", payload)

    def test_runtime_and_desktop_adr_are_document_digests_not_principals(self) -> None:
        payload = {
            "schema_version": "gocode.rc0.platform-qualified-subject/2",
            "repository_id": "gocode",
            "project_owner_authority_receipt_sha256": _HASH,
            "mapping_policy_envelope_sha256": "b" * 64,
            "active_activation_snapshot_envelope_sha256": "c" * 64,
            "platform_qualified_subject_envelope_sha256": "f" * 64,
            "runtime_adr_document_sha256": "d" * 64,
            "desktop_adr_document_sha256": "e" * 64,
        }
        validate_successor_payload("subject", payload)
        payload["runtime_platform_owner"] = "principal"
        with self.assertRaisesRegex(SuccessorContractFailure, "SUCCESSOR_PRINCIPAL_FIELD_FORBIDDEN"):
            validate_successor_payload("subject", payload)

    def test_registry_rejects_a_duplicate_schema_identity(self) -> None:
        payload = json.loads((_FIXTURES / "registry.json").read_text(encoding="utf-8"))
        payload["adjunct_schema_digests"][1]["schema_id"] = payload["adjunct_schema_digests"][0]["schema_id"]
        with self.assertRaisesRegex(SuccessorContractFailure, "SUCCESSOR_REGISTRY_SCHEMA_SET_INVALID"):
            validate_successor_payload("registry", payload)

    def test_lineage_rejects_a_receipt_hash_substitution(self) -> None:
        lineage = {
            kind: json.loads((_FIXTURES / f"{kind}.json").read_text(encoding="utf-8"))
            for kind in ("registry", "mapping", "intent", "snapshot", "subject", "matrix")
        }
        validate_successor_lineage(lineage)
        lineage["matrix"]["project_owner_authority_receipt_sha256"] = "f" * 64
        with self.assertRaisesRegex(SuccessorContractFailure, "SUCCESSOR_RECEIPT_LINEAGE_MISMATCH"):
            validate_successor_lineage(lineage)

    def test_registry_pins_actual_schema_bytes(self) -> None:
        payload = json.loads((_FIXTURES / "registry.json").read_text(encoding="utf-8"))
        for entry in payload["adjunct_schema_digests"]:
            entry["schema_sha256"] = "0" * 64
        with self.assertRaisesRegex(SuccessorContractFailure, "SUCCESSOR_REGISTRY_SCHEMA_DIGEST_INVALID"):
            validate_successor_payload("registry", payload)

    def test_lineage_rejects_each_link_mutation(self) -> None:
        lineage = {kind: json.loads((_FIXTURES / f"{kind}.json").read_text(encoding="utf-8")) for kind in ("registry", "mapping", "intent", "snapshot", "subject", "matrix")}
        validate_successor_lineage(lineage)
        edges = (("intent", "mapping_policy_envelope_sha256"), ("snapshot", "activation_intent_envelope_sha256"), ("subject", "active_activation_snapshot_envelope_sha256"), ("matrix", "platform_qualified_subject_envelope_sha256"))
        for kind, field in edges:
            with self.subTest(kind=kind, field=field):
                altered = json.loads(json.dumps(lineage))
                altered[kind][field] = "f" * 64
                with self.assertRaisesRegex(SuccessorContractFailure, "SUCCESSOR_LINEAGE_LINK_INVALID"):
                    validate_successor_lineage(altered)



if __name__ == "__main__":
    unittest.main()
