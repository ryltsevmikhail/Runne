"""Exact V3 identity receipts, without native execution or qualification."""
import copy
import unittest

from scripts.desktop.native_credential_enrollment.macos import validate_row
from scripts.desktop.native_credential_enrollment.macos_bindings import canonical_digest
from scripts.desktop.tests.test_native_credential_xpc_qualification import _row


class V3IdentityTests(unittest.TestCase):
    def test_identity_receipts_are_exact_v3_serialized_objects(self):
        row = _row()
        for role, identity in row["code_identities"].items():
            self.assertEqual(set(identity), {"identifier", "teamIdentifier", "cdhash"})
            self.assertEqual(row["tuple"][f"{role}_code_identity_sha256"], canonical_digest(identity))
        self.assertEqual(validate_row(row), [])

    def test_each_cdhash_is_bound_to_its_identity_digest(self):
        for role in _row()["code_identities"]:
            with self.subTest(role=role):
                row = _row()
                row["code_identities"][role]["cdhash"] = "f" * 40
                self.assertTrue(validate_row(row))

    def test_invalid_identities_cannot_be_repaired_by_rehashing(self):
        changes = (
            {"cdhash": "f" * 39}, {"cdhash": "F" * 40}, {"cdhash": "f" * 40 + "\n"},
            {"cdhash": 1}, {"cdhash": None}, {"teamIdentifier": "AAAAAAAAAA"},
            {"identifier": "runned"}, {"role": "desktop"},
            {"requirement": "anchor apple generic"},
        )
        for change in changes:
            with self.subTest(fields=tuple(change)):
                row = _row()
                identity = row["code_identities"]["desktop"]
                identity.update(change)
                row["tuple"]["desktop_code_identity_sha256"] = canonical_digest(identity)
                self.assertTrue(validate_row(row))

    def test_legacy_summary_is_not_an_identity_proof(self):
        row = _row()
        legacy = {
            "authority": "Developer ID Application", "binary_sha256": row["tuple"]["desktop_sha256"],
            "identifier": "com.runne.desktop", "notarized": True,
            "role": "desktop", "team_id": "758F9Z45SR",
        }
        row["code_identities"]["desktop"] = legacy
        row["tuple"]["desktop_code_identity_sha256"] = canonical_digest(legacy)
        self.assertTrue(validate_row(row))

    def test_role_swaps_are_rejected_even_with_matching_digest(self):
        row = _row()
        row["code_identities"]["desktop"] = copy.deepcopy(row["code_identities"]["writer"])
        row["tuple"]["desktop_code_identity_sha256"] = canonical_digest(row["code_identities"]["desktop"])
        self.assertTrue(validate_row(row))


if __name__ == "__main__":
    unittest.main()
