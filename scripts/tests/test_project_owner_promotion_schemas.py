"""Focused semantic parity checks for project-owner promotion contracts."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy

from scripts.project_owner_authority.schema_semantics import (
    promotion_bootstrap_errors,
    stage_envelope_errors,
)
from scripts.tests.test_promotion_bootstrap_schema import BOOTSTRAP, STAGE, bootstrap, stage
from scripts.tests.test_project_owner_authority_schemas import _errors, _schema_errors


class ProjectOwnerPromotionSchemaTests(unittest.TestCase):
    def test_bootstrap_schema_and_semantics_close_identity_and_oid_width(self) -> None:
        schema = json.loads(BOOTSTRAP.read_text(encoding="utf-8"))
        self.assertFalse(_schema_errors(schema))
        self.assertFalse(_errors(schema, bootstrap()))
        cases = (
            lambda value: value["delegations"][2].update(principal_id="principal-1"),
            lambda value: value["delegations"][2].update(controlling_account_id="account-1"),
            lambda value: value["delegations"][2].update(lane_id="lane-1"),
            lambda value: value["delegations"][2].update(key_id="1" * 64),
            lambda value: value["delegations"][2].update(public_key="A" * 43),
            lambda value: value["subject"].update(object_format="sha256"),
            lambda value: value.update(not_before="2026-08-13T00:00:00Z"),
        )
        for mutate in cases:
            value = deepcopy(bootstrap())
            mutate(value)
            self.assertTrue(_errors(schema, value) or promotion_bootstrap_errors(value))

    def test_transition_stage_schema_rejects_missing_identity_and_nested_self_hash(self) -> None:
        schema = json.loads(STAGE.read_text(encoding="utf-8"))
        self.assertFalse(_schema_errors(schema))
        self.assertFalse(_errors(schema, stage()))
        cases = (
            lambda value: value.pop("issuer_controlling_account_id"),
            lambda value: value.pop("issuer_lane_id"),
            lambda value: value.pop("signature_profile_id"),
            lambda value: value.pop("authorization_nonce"),
            lambda value: value["payload"].update(nested={"envelope_sha256": "f" * 64}),
            lambda value: value.update(payload_schema_id="gocode.release.rc2-signed-artifact-record/1"),
        )
        for mutate in cases:
            value = deepcopy(stage())
            mutate(value)
            self.assertTrue(_errors(schema, value) or stage_envelope_errors(value))


if __name__ == "__main__":
    unittest.main()
