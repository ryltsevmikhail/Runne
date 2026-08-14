"""Closed JSON Schema contracts for promotion bootstrap and stage envelopes."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy

from scripts.tests.test_project_owner_authority_schemas import ROOT, _errors, _schema_errors
from scripts.project_owner_authority.schema_semantics import promotion_bootstrap_errors, stage_envelope_errors


BOOTSTRAP = ROOT / "docs/schemas/project-owner-authority-receipt-v4.schema.json"
STAGE = ROOT / "docs/schemas/release-post-rc0-stage-envelope-v1.schema.json"


def delegation(role: str, number: int) -> dict[str, object]:
    schema = {"RC1_QUALIFICATION_AUTHORIZER": "gocode.release.rc1-qualification-decision/1", "RC2_SIGNING_AUTHORIZER": "gocode.release.rc2-signing-authorization/1", "RC3_PUBLICATION_AUTHORIZER": "gocode.release.rc3-publication-authorization/1"}[role]
    return {"role": role, "principal_id": f"principal-{number}", "controlling_account_id": f"account-{number}", "lane_id": f"lane-{number}", "key_id": str(number) * 64, "public_key": "A" * 43, "key_epoch": 1, "signature_profile_id": f"profile-{number}", "not_before": "2026-08-13T00:00:01Z", "expires_at": "2026-08-13T00:00:03Z", "revocation_epoch": 1, "allowed_payload_schema_ids": [schema]}


def bootstrap() -> dict[str, object]:
    return {"schema_version": "gocode.project-owner.authority-receipt/4", "repository_id": "gocode", "role": "PROJECT_OWNER", "purpose": "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP", "profile": "gocode.project-owner.post-rc0-promotion/1", "predecessor_receipt_sha256": "1" * 64, "platform_qualified_subject_sha256": "2" * 64, "platform_matrix_sha256": "3" * 64, "promotion_policy_sha256": "4" * 64, "promotion_policy_revision": "policy-1", "authority_store_profile": "authority-store-1", "root_principal_id":"root-principal", "root_controlling_account_id":"root-account", "root_lane_id":"root-lane", "root_signature_profile_id":"root-profile", "issued_at": "2026-08-13T00:00:00Z", "not_before": "2026-08-13T00:00:01Z", "expires_at": "2026-08-13T00:00:04Z", "revocation_epoch": 1, "delegations": [delegation("RC1_QUALIFICATION_AUTHORIZER", 1), delegation("RC2_SIGNING_AUTHORIZER", 2), delegation("RC3_PUBLICATION_AUTHORIZER", 3)], "subject": {"object_format": "sha1", "commit_oid": "5" * 40, "tree_oid": "6" * 40}, "documents": [{"path": "docs/adr/ADR-0028-promotion-and-release-authority-v2.md", "mode": "100644", "blob_oid": "7" * 40, "content_sha256": "8" * 64, "byte_length": 1}, {"path": "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md", "mode": "100644", "blob_oid": "9" * 40, "content_sha256": "a" * 64, "byte_length": 1}], "trust_config_sha256": "b" * 64, "key_id": "c" * 64, "key_epoch": 3, "signature": "A" * 86}


def stage() -> dict[str, object]:
    return {"schema_version": "gocode.release.post-rc0-stage-envelope/1", "repository_id": "gocode", "bootstrap_receipt_sha256": "1" * 64, "issuer_role": "RC1_QUALIFICATION_AUTHORIZER", "issuer_principal_id": "principal-1", "issuer_controlling_account_id": "account-1", "issuer_lane_id": "lane-1", "issuer_key_id": "2" * 64, "issuer_key_epoch": 1, "signature_profile_id": "profile-1", "payload_schema_id": "gocode.release.rc1-qualification-decision/1", "payload_schema_sha256": "3" * 64, "payload_sha256": "4" * 64, "payload": {"schema_version": "gocode.release.rc1-qualification-decision/1"}, "issued_at": "2026-08-13T00:00:00Z", "not_before": "2026-08-13T00:00:01Z", "expires_at": "2026-08-13T00:00:02Z", "revocation_epoch": 1, "authorization_nonce": "nonce-1", "signature": "A" * 86}


class PromotionBootstrapSchemas(unittest.TestCase):
    def test_closed_bootstrap_contract_rejects_reordered_or_reused_delegations(self) -> None:
        schema = json.loads(BOOTSTRAP.read_text(encoding="utf-8"))
        self.assertEqual(schema["$id"], "gocode.project-owner.authority-receipt/4")
        self.assertFalse(_schema_errors(schema)); self.assertFalse(_errors(schema, bootstrap()))
        for mutate in (lambda v: v["delegations"].reverse(), lambda v: v["delegations"][1].update(principal_id="principal-1"), lambda v: v["delegations"][1].update(controlling_account_id="account-1"), lambda v: v["delegations"][1].update(lane_id="lane-1"), lambda v: v["delegations"][1].update(key_id="1" * 64), lambda v: v["delegations"][1].update(public_key="A" * 43), lambda v: v.update(root_principal_id="-unsafe"), lambda v: v["delegations"][0].update(principal_id="-unsafe"), lambda v: v["documents"].pop(), lambda v: v.update(expires_at="not-a-date"), lambda v: v["documents"][0].update(blob_oid="7" * 64)):
            value = deepcopy(bootstrap()); mutate(value); self.assertTrue(_errors(schema, value) or promotion_bootstrap_errors(value))

    def test_closed_stage_contract_rejects_enclosing_hash_and_wrong_role_schema(self) -> None:
        schema = json.loads(STAGE.read_text(encoding="utf-8"))
        self.assertEqual(schema["$id"], "gocode.release.post-rc0-stage-envelope/1")
        self.assertFalse(_schema_errors(schema)); self.assertFalse(_errors(schema, stage()))
        for mutate in (lambda v: v["payload"].update(envelope_sha256="f" * 64), lambda v: v["payload"].update(nested={"stage_envelope_sha256":"f" * 64}), lambda v: v.update(payload_schema_id="gocode.release.rc3-publication-authorization/1"), lambda v: v.update(authorization_nonce="unsafe/slash"), lambda v: v.pop("issuer_lane_id"), lambda v: v.update(signature_profile_id="unsafe/slash")):
            value = deepcopy(stage()); mutate(value); self.assertTrue(_errors(schema, value) or stage_envelope_errors(value))


if __name__ == "__main__":
    unittest.main()
