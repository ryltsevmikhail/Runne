"""Strict, production-owned accepted-ADR parsing vectors."""

from __future__ import annotations

import unittest

from scripts.rc0_policy.governance_status import GovernanceStatusFailure, accepted_adr_digests, parse_accepted_adr


def accepted() -> bytes:
    return b"---\nstatus: ready\nowners:\n  - gocode-runtime\n---\n\n# ADR-0027: Scope\n\n**Status:** accepted\n"


def accepted_with_digests() -> bytes:
    return accepted() + b"\n- `shared_decision_payload_sha256`: `" + b"a" * 64 + b"`\n- `shared_decision_schema_sha256`: `" + b"b" * 64 + b"`\n"


class GovernanceStatusTests(unittest.TestCase):
    def test_accepts_one_exact_visible_status_token(self) -> None:
        self.assertIsNone(parse_accepted_adr(accepted(), "ADR-0027", "runtime"))

    def test_rejects_substring_negation_superseded_duplicate_or_malformed_adr(self) -> None:
        vectors = (
            accepted().replace(b"accepted", b"not accepted"),
            accepted().replace(b"accepted", b"superseded"),
            accepted() + b"\n**Status:** accepted\n",
            accepted().replace(b"# ADR-0027", b"# ADR-00270"),
            accepted().replace(b"status: ready", b"status: accepted"),
            accepted().replace(b"---\n\n#", b"#"),
        )
        for raw in vectors:
            with self.subTest(raw=raw), self.assertRaises(GovernanceStatusFailure):
                parse_accepted_adr(raw, "ADR-0027", "runtime")

    def test_extracts_one_exact_shared_decision_digest_pair(self) -> None:
        self.assertEqual(accepted_adr_digests(accepted_with_digests(), "ADR-0027", "runtime"), ("a" * 64, "b" * 64))
        with self.assertRaises(GovernanceStatusFailure):
            accepted_adr_digests(accepted_with_digests().replace(b"`" + b"b" * 64, b"`" + b"g" * 64), "ADR-0027", "runtime")


if __name__ == "__main__":
    unittest.main()
