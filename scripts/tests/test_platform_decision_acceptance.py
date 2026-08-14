"""Fixture-only platform owner acceptance checks."""

import unittest

from scripts.rc0_policy.platform_policy import PolicyFailure, fixture_verify_mapping_policy
from scripts.tests.rc0_platform_policy_support import valid_mapping_fixture


class DecisionAcceptanceTests(unittest.TestCase):
    def test_proposed_repository_adrs_reject_mapping(self) -> None:
        fixture = valid_mapping_fixture()
        rejected = fixture.__class__(**{**fixture.__dict__, "runtime_adr_raw": fixture.runtime_adr_raw.replace(b"accepted", b"proposed")})
        with self.assertRaisesRegex(PolicyFailure, "ADR_NOT_ACCEPTED"):
            fixture_verify_mapping_policy(**rejected.arguments())

    def test_mapping_accepts_distinct_verified_owner_bindings(self) -> None:
        fixture = valid_mapping_fixture()
        mapping = fixture_verify_mapping_policy(**fixture.arguments())
        self.assertNotEqual(mapping.governance_authorities[0], mapping.governance_authorities[1])


if __name__ == "__main__":
    unittest.main()
