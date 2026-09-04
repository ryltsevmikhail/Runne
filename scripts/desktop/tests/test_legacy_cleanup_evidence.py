"""Structural evidence validation; fixtures never represent native qualification."""
import copy
import unittest

from scripts.desktop.native_credential_enrollment import legacy_cleanup


CASES = (
    "authorized_import", "durable_cutover", "replacement_denied",
    "ambiguous_source_denied", "exact_source_deleted",
    "restart_after_delete_before_confirmation", "reimport_denied",
)


def evidence():
    return {
        "schema_version": "legacy-source-cleanup-evidence.v1",
        "candidate_sha256": "a" * 64, "tuple_sha256": "b" * 64,
        "workflow_run_id": "isolated-run-1",
        "selectors": {name: {"status": "verified", "observation_sha256": "c" * 64}
                      for name in CASES},
    }


def validate(value):
    return legacy_cleanup.validate_evidence(
        value, candidate_sha256="a" * 64, tuple_sha256="b" * 64,
        workflow_run_id="isolated-run-1",
    )


class LegacyCleanupEvidenceTests(unittest.TestCase):
    def test_exact_structural_fixture(self):
        self.assertEqual(validate(evidence()), [])

    def test_every_native_case_is_mandatory(self):
        for name in CASES:
            value = evidence()
            del value["selectors"][name]
            self.assertTrue(validate(value), name)

    def test_foreign_candidate_tuple_and_run_are_rejected(self):
        for field in ("candidate_sha256", "tuple_sha256", "workflow_run_id"):
            value = evidence()
            value[field] = "d" * 64
            self.assertTrue(validate(value), field)

    def test_missing_failed_and_sensitive_receipts_are_rejected(self):
        for receipt in (None, {}, {"status": "unsupported", "observation_sha256": "c" * 64},
                        {"status": "verified", "observation_sha256": "0" * 64},
                        {"status": "verified", "observation_sha256": "c" * 64, "secret": "canary"}):
            value = evidence()
            value["selectors"]["authorized_import"] = copy.deepcopy(receipt)
            self.assertTrue(validate(value))

    def test_malformed_envelopes_and_unknown_fields_are_rejected(self):
        for value in (None, [], {}, {**evidence(), "native_path": "canary"},
                      {**evidence(), "schema_version": "native-credential-enrollment-evidence.v1"},
                      {**evidence(), "selectors": []}):
            self.assertTrue(validate(value))
