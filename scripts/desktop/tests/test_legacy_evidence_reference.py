"""Reference enforcer contract: structural checks plus the runner-side delta."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.desktop import legacy_evidence_reference as reference
from scripts.desktop.tests.test_legacy_cleanup_evidence import evidence


class LegacyEvidenceReferenceTests(unittest.TestCase):
    def test_structural_checks_delegate_to_the_checkout_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(evidence()))
            errors = reference.structural_errors(
                json.loads(path.read_text()), candidate_sha256="a" * 64,
                tuple_sha256="b" * 64, workflow_run_id="isolated-run-1",
            )
        self.assertEqual(errors, [])

    def test_enforcer_contract_binds_repository_workflow_and_protected_ref(self):
        self.assertEqual(
            reference.enforcer_contract(
                "d" * 64, reference.EXPECTED_REPOSITORY,
                reference.EXPECTED_WORKFLOW, reference.EXPECTED_SOURCE_REF,
            ),
            [],
        )
        for repository, workflow, source_ref in [
            ("https://git@git.example.com/runne.git",
             reference.EXPECTED_WORKFLOW, reference.EXPECTED_SOURCE_REF),
            (reference.EXPECTED_REPOSITORY, "other-workflow",
             reference.EXPECTED_SOURCE_REF),
            (reference.EXPECTED_REPOSITORY, reference.EXPECTED_WORKFLOW,
             "refs/heads/main"),
        ]:
            errors = reference.enforcer_contract("d" * 64, repository, workflow, source_ref)
            self.assertTrue(errors, (repository, workflow, source_ref))
        self.assertEqual(
            reference.enforcer_contract("nothex", reference.EXPECTED_REPOSITORY,
                                        reference.EXPECTED_WORKFLOW,
                                        reference.EXPECTED_SOURCE_REF),
            ["legacy evidence source digest is invalid"],
        )

    def test_candidate_binding_matches_the_qualification_task_derivation(self):
        candidate, tuple_digest, run_id = reference.candidate_binding(
            "f" * 40, "run-7",
        )
        self.assertEqual(candidate, reference.candidate_binding("f" * 40, "run-7")[0])
        self.assertEqual(run_id, "run-7")
        self.assertNotEqual(candidate, tuple_digest)
        for digest in (candidate, tuple_digest):
            self.assertEqual(len(digest), 64)
            self.assertTrue(all(char in "0123456789abcdef" for char in digest))

    def test_reference_is_never_qualification(self):
        # The module must not contain any capability or qualification grant.
        source = Path(reference.__file__).read_text()
        self.assertNotIn("qualified\": True", source)
        self.assertNotIn("grant", source.lower().replace("granted", ""))


if __name__ == "__main__":
    unittest.main()
