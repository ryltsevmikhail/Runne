import importlib
import json
import unittest
from collections import UserDict
from decimal import Decimal


def canonical_module():
    try:
        return importlib.import_module("scripts.rc0_policy.canonical")
    except ModuleNotFoundError as error:
        raise AssertionError("strict RC0 fixture parser is absent") from error


class Rc0PolicyCanonicalTests(unittest.TestCase):
    def test_rejects_duplicate_key_invalid_utf8_depth_and_size_limits(self):
        canonical = canonical_module()
        invalid = (
            b'{"a":1,"a":2}',
            b'\xff',
            (b'{"a":' * 33) + b'0' + (b'}' * 33),
            b' ' * 65537,
            json.dumps([0] * 4097).encode(),
            json.dumps("x" * 4097).encode(),
        )
        for raw in invalid:
            with self.subTest(raw_length=len(raw)):
                with self.assertRaises(canonical.StrictJSONError):
                    canonical.loads_canonical(raw)

    def test_rejects_nan_float_and_unknown_property(self):
        canonical = canonical_module()
        schemas = importlib.import_module("scripts.rc0_policy.schemas")
        for raw in (b'NaN', b'Infinity', b'1.0'):
            with self.subTest(raw=raw):
                with self.assertRaises(canonical.StrictJSONError):
                    canonical.loads_canonical(raw)
        record = {
            "candidate_source_revision": "a" * 40,
            "evidence_attempt_id": "018f0000-0000-7000-8000-000000000000",
            "policy_digest": "b" * 64,
            "profile": "gocode.rc0.evidence-profile/3",
            "repository_id": "gocode",
            "schema_id": "gocode.rc0.schema.candidate-record/3",
            "unknown": True,
        }
        diagnostics = schemas.validate_schema(
            record, "gocode.rc0.schema.candidate-record/3"
        )
        self.assertTrue(any("unknown" in diagnostic for diagnostic in diagnostics))

    def test_canonical_output_is_nfc_and_utf8_key_sorted(self):
        canonical = canonical_module()
        with self.assertRaises(canonical.StrictJSONError):
            canonical.loads_canonical('"e\u0301"'.encode())
        parsed = canonical.loads_canonical(b'{"z":1,"a":2}')
        self.assertEqual(canonical.canonical_bytes(parsed), b'{"a":2,"z":1}')

    def test_canonical_bytes_rejects_non_profile_python_values(self):
        canonical = canonical_module()
        invalid = (
            {"value": 1.0},
            {"value": Decimal("1")},
            {1: "silently-stringified-key"},
            UserDict({"value": 1}),
            {"value": 2**64},
            {"value": "e\u0301"},
            {"value": "\ud800"},
        )
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                try:
                    canonical.canonical_bytes(value)
                except canonical.StrictJSONError:
                    pass
                except Exception as error:
                    self.fail(f"canonicalization leaked {type(error).__name__}")
                else:
                    self.fail("canonicalization accepted a non-profile value")

    def test_canonical_bytes_enforces_exact_emitted_document_limit(self):
        canonical = canonical_module()
        exact_ascii = ["a" * 4096] * 15 + ["b" * 4047]
        exact_nfc = ["é" * 2048] * 15 + [("é" * 2023) + "x"]
        self.assertEqual(len(canonical.canonical_bytes(exact_ascii)), 65536)
        self.assertEqual(len(canonical.canonical_bytes(exact_nfc)), 65536)
        with self.assertRaises(canonical.StrictJSONError):
            canonical.canonical_bytes(["a" * 4096] * 15 + ["b" * 4048])
        with self.assertRaises(canonical.StrictJSONError):
            canonical.canonical_bytes(["\x00" * 4096] * 3)


if __name__ == "__main__":
    unittest.main()
