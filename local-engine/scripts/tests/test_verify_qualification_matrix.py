"""Verifier tests (Plan Task 22 Step 1): schema violations, digest-less
entries, missing evidence refs and empty-evidence capability claims
reject; the committed matrix passes."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MATRIX = REPO_ROOT / "docs/profiles/local-engine/PHASE1_QUALIFICATION_MODELS.json"
VERIFIER = REPO_ROOT / "scripts/local-engine/verify-qualification-matrix.py"

_SPEC = importlib.util.spec_from_file_location("verify_qualification_matrix", VERIFIER)
vqm = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(vqm)


class VerifyQualificationMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        # A resolvable evidence file for the happy path.
        self.evidence = self.root / "evidence.md"
        self.evidence.write_text("evidence", encoding="utf-8")
        for entry in self.matrix["entries"]:
            entry["evidence_ref"] = "evidence.md"

    def verify(self, matrix: dict) -> int:
        return vqm.verify_matrix(matrix, self.root)

    def test_committed_matrix_passes(self) -> None:
        code = vqm.main_with_paths(MATRIX, REPO_ROOT)
        self.assertEqual(code, 0)

    def test_bad_schema_version_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["schema_version"] = "SomethingElse"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_digest_less_entry_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["artifact_digest"] = "deadbeef"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_missing_evidence_ref_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["evidence_ref"] = ""
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_dangling_evidence_ref_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["evidence_ref"] = "no/such/file.md"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_empty_capabilities_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["capabilities"] = []
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_unknown_field_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["surprise"] = True
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_duplicate_entry_id_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"].append(copy.deepcopy(m["entries"][0]))
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_zero_byte_length_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["byte_length"] = 0
        with self.assertRaises(vqm.Rejection):
            self.verify(m)


if __name__ == "__main__":
    unittest.main()
