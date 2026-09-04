"""Exercise the published structural schema against receipts, not source text."""
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.desktop.tests.test_legacy_cleanup_evidence import CASES, evidence


class LegacyCleanupSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[3] / "docs/schemas/legacy-source-cleanup-evidence-v1.schema.json"
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema)

    def test_valid_envelope(self):
        self.validator.validate(evidence())

    def test_missing_cases_and_unknown_fields_fail(self):
        for name in CASES:
            value = evidence()
            del value["selectors"][name]
            self.assertFalse(self.validator.is_valid(value))
        self.assertFalse(self.validator.is_valid({**evidence(), "secret": "canary"}))

    def test_invalid_digest_status_and_run_fail(self):
        for field, value in [("candidate_sha256", "0" * 64), ("tuple_sha256", "G" * 64),
                             ("workflow_run_id", "  ")]:
            self.assertFalse(self.validator.is_valid({**evidence(), field: value}))
        value = evidence()
        value["selectors"]["exact_source_deleted"]["status"] = "unsupported"
        self.assertFalse(self.validator.is_valid(value))
