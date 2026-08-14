"""Focused boundary vectors for the encrypted owner-key backup schema."""

import unittest
from copy import deepcopy

from scripts.tests import test_project_owner_authority_schemas as authority_schemas


class ProjectOwnerBackupSchemaTests(unittest.TestCase):
    def test_binary_lengths_and_kdf_bounds(self) -> None:
        schema = authority_schemas._schema("backup-metadata")
        valid = authority_schemas.load_fixture("backup-metadata")
        self.assertFalse(authority_schemas._errors(schema, valid))
        for field, value in (
            ("salt", "A" * 21),
            ("salt", "A" * 87),
            ("nonce", "A" * 31),
            ("ciphertext", "A" * 63),
            ("ciphertext", "A" * 65),
        ):
            with self.subTest(field=field, value=value):
                changed = deepcopy(valid)
                changed[field] = value
                self.assertTrue(authority_schemas._errors(schema, changed))
        for field, value in (
            ("memory_kib", 65_535),
            ("memory_kib", 262_145),
            ("iterations", 2),
            ("iterations", 11),
            ("parallelism", 0),
            ("parallelism", 5),
        ):
            with self.subTest(field=field, value=value):
                changed = deepcopy(valid)
                changed["kdf"][field] = value
                self.assertTrue(authority_schemas._errors(schema, changed))


if __name__ == "__main__":
    unittest.main()
