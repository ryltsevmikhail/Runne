"""Semantic trust/rotation boundary vectors beyond structural JSON Schema."""

import unittest
from copy import deepcopy

from scripts.tests import test_project_owner_authority_schemas as authority_schemas
from scripts.project_owner_authority.schema_semantics import trust_config_errors


class ProjectOwnerTrustSchemaTests(unittest.TestCase):
    def test_unique_schema_ids_and_u64_epoch_bounds(self) -> None:
        trust = authority_schemas.load_fixture("trust-config")
        duplicate = deepcopy(trust["schema_digests"][0])
        duplicate["schema_sha256"] = "f" * 64
        trust["schema_digests"].append(duplicate)
        self.assertTrue(trust_config_errors(trust))

        reversed_trust = authority_schemas.load_fixture("trust-config")
        reversed_trust["schema_digests"] = [
            {"schema_id": "gocode.z/1", "schema_sha256": "a" * 64},
            {"schema_id": "gocode.a/1", "schema_sha256": "b" * 64},
        ]
        self.assertTrue(trust_config_errors(reversed_trust))

        trust = authority_schemas.load_fixture("trust-config")
        trust["epoch"] = 1 << 64
        self.assertTrue(
            authority_schemas._errors(authority_schemas._schema("trust-config"), trust)
        )
        rotation = authority_schemas.load_fixture("rotation")
        rotation["new_epoch"] = 1 << 64
        self.assertTrue(
            authority_schemas._errors(authority_schemas._schema("rotation"), rotation)
        )


if __name__ == "__main__":
    unittest.main()
