"""Strict canonical codec tests for large in-memory attestation graphs."""

from __future__ import annotations

import unittest

from scripts.rc0_policy.canonical import (
    StrictJSONError,
    canonical_bytes,
    loads_canonical,
)
from scripts.rc0_policy.composite_canonical import (
    MAX_COMPOSITE_DOCUMENT_BYTES,
    canonical_composite_bytes,
    loads_composite_canonical,
)


class CompositeCanonicalTests(unittest.TestCase):
    def test_round_trips_an_attestation_sized_graph_beyond_envelope_cap(self) -> None:
        value = {"evidence_envelopes": ["x" * 4_000 for _ in range(21)]}

        raw = canonical_composite_bytes(value)

        self.assertGreater(len(raw), 82_000)
        self.assertLess(len(raw), 85_000)
        self.assertEqual(loads_composite_canonical(raw), value)
        with self.assertRaises(StrictJSONError):
            canonical_bytes(value)
        with self.assertRaises(StrictJSONError):
            loads_canonical(raw)

    def test_composite_codec_uses_identical_canonical_json_for_small_values(self) -> None:
        value = {"a": ["value", 2], "z": {"b": True}}

        self.assertEqual(canonical_composite_bytes(value), canonical_bytes(value))
        self.assertEqual(loads_composite_canonical(canonical_bytes(value)), value)

    def test_composite_codec_rejects_invalid_or_noncanonical_raw(self) -> None:
        for raw in (
            b'{"z":1, "a":2}',
            b'{"a":1,"a":2}',
            b'\xef\xbb\xbf{"a":1}',
            b"{\"a\":-0}",
            b"x" * (MAX_COMPOSITE_DOCUMENT_BYTES + 1),
        ):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(StrictJSONError):
                    loads_composite_canonical(raw)


if __name__ == "__main__":
    unittest.main()
