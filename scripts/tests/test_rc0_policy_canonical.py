import importlib
import json
import unittest


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


if __name__ == "__main__":
    unittest.main()
