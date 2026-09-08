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
        self.profile = self.root / "docs/profiles/local-engine/PHASE1_BACKEND_PROFILE.json"
        self.profile.parent.mkdir(parents=True)
        self.profile.write_text(
            json.dumps(
                {
                    "schema_version": "Phase1BackendProfileV1",
                    "profile_ids": [
                        "llama-cpp-cpu-macos-arm64-v1",
                        "llama-cpp-metal-macos-arm64-v1",
                    ],
                }
            ),
            encoding="utf-8",
        )
        for entry in self.matrix["entries"]:
            self.write_evidence(entry)

    def write_evidence(self, entry: dict, *, artifact_digest: str | None = None) -> Path:
        evidence = (
            self.root
            / "docs/golden/local-engine/evidence"
            / f"{entry['entry_id']}.md"
        )
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(
            "\n".join(
                (
                    f"# Evidence — {entry['entry_id']}",
                    "",
                    f"Qualification evidence for matrix entry `{entry['entry_id']}`.",
                    "",
                    "| Field | Value |",
                    "|---|---|",
                    f"| matrix_revision | `{self.matrix['matrix_revision']}` |",
                    f"| artifact_digest | `{artifact_digest or entry['artifact_digest']}` |",
                    f"| byte_length | {entry['byte_length']} |",
                    f"| quantization_class | `{entry['quantization_class']}` |",
                    "| interpretation_revisions | "
                    + ", ".join(
                        f"{key} `{value}`"
                        for key, value in entry["interpretation_revisions"].items()
                    )
                    + " |",
                    f"| backend_profile | `{entry['backend_profile']}` |",
                    f"| hardware_class | `{entry['hardware_class']}` |",
                    "| capabilities | "
                    + ", ".join(f"`{capability}`" for capability in entry["capabilities"])
                    + " |",
                    "",
                )
            ),
            encoding="utf-8",
        )
        entry["evidence_ref"] = evidence.relative_to(self.root).as_posix()
        return evidence

    def verify(self, matrix: dict) -> int:
        return vqm.verify_matrix(matrix, self.root)

    def test_committed_matrix_passes(self) -> None:
        code = vqm.main_with_paths(MATRIX, REPO_ROOT)
        self.assertEqual(code, 0)

    def test_complete_evidence_contract_passes(self) -> None:
        self.assertEqual(self.verify(self.matrix), len(self.matrix["entries"]))

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
        m["entries"][0]["evidence_ref"] = "docs/golden/local-engine/evidence/no-such-file.md"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_absolute_evidence_ref_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["evidence_ref"] = str(
            self.root / "docs/golden/local-engine/evidence/entry-llama-q4-fixture.md"
        )
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_parent_traversal_evidence_ref_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["evidence_ref"] = (
            "docs/golden/local-engine/evidence/../evidence/entry-llama-q4-fixture.md"
        )
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_symlink_escape_evidence_ref_rejects(self) -> None:
        outside = self.root.parent / "outside-evidence.md"
        outside.write_text("untrusted", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        link = self.root / "docs/golden/local-engine/evidence/entry-llama-q4-fixture.md"
        link.unlink()
        link.symlink_to(outside)
        with self.assertRaises(vqm.Rejection):
            self.verify(self.matrix)

    def test_unrelated_evidence_ref_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        unrelated = self.root / "README.md"
        unrelated.write_text("not qualification evidence", encoding="utf-8")
        m["entries"][0]["evidence_ref"] = "README.md"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_must_bind_exact_entry_digest(self) -> None:
        m = copy.deepcopy(self.matrix)
        self.write_evidence(m["entries"][0], artifact_digest="sha256:" + "0" * 64)
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_digest_must_be_a_bound_field(self) -> None:
        m = copy.deepcopy(self.matrix)
        entry = m["entries"][0]
        evidence = self.write_evidence(entry)
        evidence.write_text(
            "\n".join(
                (
                    f"# Evidence — {entry['entry_id']}",
                    "",
                    f"Historical artifact digest: `{entry['artifact_digest']}`.",
                    f"| backend_profile | `{entry['backend_profile']}` |",
                    "",
                )
            ),
            encoding="utf-8",
        )
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_header_must_bind_exact_entry_id(self) -> None:
        m = copy.deepcopy(self.matrix)
        entry = m["entries"][0]
        evidence = self.write_evidence(entry)
        evidence.write_text(
            evidence.read_text(encoding="utf-8").replace(
                f"# Evidence — {entry['entry_id']}",
                f"# Evidence — {entry['entry_id']}-other",
            ),
            encoding="utf-8",
        )
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_must_bind_declared_backend_profile(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["backend_profile"] = "llama-cpp-metal-macos-arm64-v1"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_must_bind_matrix_revision(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["matrix_revision"] = "2026-09-08-r3"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_must_bind_declared_byte_length(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["byte_length"] += 1
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_must_bind_declared_quantization_class(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["quantization_class"] = "q5_0"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_must_bind_declared_interpretation_revisions(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["interpretation_revisions"]["tokenizer"] = "2"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_must_bind_declared_hardware_class(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["hardware_class"] = "macos-arm64-min-32gb"
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_evidence_must_bind_declared_capabilities(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["capabilities"].append("tools")
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_unknown_backend_profile_rejects(self) -> None:
        m = copy.deepcopy(self.matrix)
        m["entries"][0]["backend_profile"] = "unreviewed-backend-v1"
        self.write_evidence(m["entries"][0])
        with self.assertRaises(vqm.Rejection):
            self.verify(m)

    def test_unsupported_backend_profile_schema_rejects(self) -> None:
        profile = json.loads(self.profile.read_text(encoding="utf-8"))
        profile["schema_version"] = "UnreviewedBackendProfileV1"
        self.profile.write_text(json.dumps(profile), encoding="utf-8")
        with self.assertRaises(vqm.Rejection):
            self.verify(self.matrix)

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
