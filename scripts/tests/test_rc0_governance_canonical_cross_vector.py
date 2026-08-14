"""Cross-vector check for the separate governance LF convention."""

import unittest

from scripts.rc0_policy.canonical import canonical_bytes
from scripts.tests.test_v1_platform_scope_governance import canonical_json_bytes


class GovernanceCanonicalCrossVectorTests(unittest.TestCase):
    def test_governance_lf_representation_extends_shared_canonical_bytes(self) -> None:
        value = {"a": ["ascii", {"b": 2}], "z": "value"}
        self.assertEqual(canonical_json_bytes(value), canonical_bytes(value) + b"\n")


if __name__ == "__main__":
    unittest.main()
