"""V2 successor-trust schema parity and negative vectors."""

import json
import unittest
from copy import deepcopy
from pathlib import Path

from scripts.project_owner_authority.schema_semantics import trust_v2_errors
from scripts.tests.test_project_owner_authority_schemas import ROOT, _errors


PINS = [
    "gocode.governance.v1-platform-scope-decision/1",
    "gocode.project-owner.authority-receipt/2",
    "gocode.project-owner.authority-receipt/3",
    "gocode.rc0.post-rc0-platform-composed-universe/1",
    "gocode.v1-platform-scope-claim-migration/1",
]


def config() -> dict:
    return {
        "schema_version": "gocode.project-owner.trust-config/2", "repository_id": "gocode", "role": "PROJECT_OWNER", "epoch": 2,
        "key_id": "a" * 64, "public_key": "A" * 43,
        "schema_digests": [{"schema_id": item, "schema_sha256": "b" * 64} for item in PINS],
        "proof_of_possession": "A" * 86, "predecessor": "c" * 64,
        "predecessor_schema_version": "gocode.project-owner.trust-config/1",
    }


class ProjectOwnerTrustV2SchemaTests(unittest.TestCase):
    def test_v2_requires_a_complete_monotonic_successor_pin_union(self) -> None:
        schema = json.loads((ROOT / "docs/schemas/project-owner-trust-config-v2.schema.json").read_text())
        value = config()
        self.assertFalse(_errors(schema, value))
        self.assertFalse(trust_v2_errors(value))
        for mutation in (
            lambda candidate: candidate["schema_digests"].pop(),
            lambda candidate: candidate["schema_digests"].reverse(),
            lambda candidate: candidate["schema_digests"].append({"schema_id": "gocode.extra/1", "schema_sha256": "d" * 64}),
            lambda candidate: candidate.update(predecessor_schema_version="gocode.project-owner.trust-config/2"),
        ):
            candidate = deepcopy(value)
            mutation(candidate)
            self.assertTrue(_errors(schema, candidate) or trust_v2_errors(candidate))


if __name__ == "__main__":
    unittest.main()
