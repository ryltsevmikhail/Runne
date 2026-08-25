import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.desktop.validate_qualification_matrices import validate_matrices
from scripts.desktop.tests.test_validate_qualification_matrices import _write_matrix_tree


MATRIX_DOCS = {
    "docs/desktop/06-design-system/ACCESSIBILITY_TEST_MATRIX.md": ("| Check | Automated | Manual |", "No P0/P1 accessibility defect"),
    "docs/desktop/06-design-system/LOCALIZATION.md": ("v1 product locales: Russian and English.", "bidi isolation"),
    "docs/desktop/07-testing/SECURITY_ABUSE_CASES.md": ("| ID | Attack | Expected result |", "| SA-018 |"),
    "docs/desktop/03-desktop/ERROR_AND_DEGRADED_STATE_MATRIX.md": ("| Condition | Visible state | Allowed | Primary recovery |", "no duplicate command"),
}
POLICY = {"repository": "https://git@git.sourcecraft.dev/org/repo.git", "workflow": "desktop-qualification", "source_ref": "refs/tags/v1.0.0", "signer": "desktop-release-attestor"}
SOURCE_REF = "refs/tags/v1.0.0"
SOURCE_DIGEST = "a" * 40


def _write_verified_canonical_tree(root: Path) -> None:
    for relative, body_markers in MATRIX_DOCS.items():
        matrix_path = root / relative
        matrix_path.parent.mkdir(parents=True, exist_ok=True)
        matrix_path.write_text(
            "---\nqualification_evidence: "
            + json.dumps({"schema_version": "desktop-qualification-matrix.v1", "disposition": "verified", "evidence_ref": f"docs/evidence/desktop-qualification/{matrix_path.stem}.json", "p0_p1_disposition": "verified"}, separators=(",", ":"))
            + "\n---\n" + "\n".join(body_markers) + "\n", encoding="utf-8"
        )
        evidence = root / "docs/evidence/desktop-qualification" / f"{matrix_path.stem}.json"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(
            json.dumps({
                "schema_version": "desktop-qualification-evidence.v1", "matrix_path": relative,
                "matrix_sha256": hashlib.sha256(matrix_path.read_bytes()).hexdigest(), "source_ref": SOURCE_REF, "source_digest": SOURCE_DIGEST,
                "producer": "protected-runner", "provenance_ref": "https://attest.example.invalid/runs/1",
                "p0_p1_disposition": "verified",
                "results": [{"row_id": "P0", "disposition": "verified", "result": "passed"}, {"row_id": "P1", "disposition": "verified", "result": "passed"}],
            }, separators=(",", ":")), encoding="utf-8"
        )


class ExternalQualificationEvidenceTest(unittest.TestCase):
    def test_accepts_only_a_valid_record_in_the_temporary_canonical_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            for evidence in (root / "docs/evidence/desktop-qualification").glob("*.json"):
                evidence.with_name(evidence.name + ".intoto.jsonl").write_text("bundle\n", encoding="utf-8")
            with patch("scripts.desktop.validate_qualification_matrices.verify_attestation", return_value={"verified": True}):
                errors = validate_matrices(root, verify_external=True, source_ref=SOURCE_REF, source_digest=SOURCE_DIGEST, attestation_policy=POLICY)
        self.assertEqual(errors, [])

    def test_synthetic_canonical_json_requires_external_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            errors = validate_matrices(root)
        self.assertTrue(any("qualification evidence requires external verification" in error for error in errors))

    def test_external_verification_requires_the_adjacent_sigstore_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            errors = validate_matrices(root, verify_external=True, source_ref=SOURCE_REF, source_digest=SOURCE_DIGEST, attestation_policy=POLICY)
        self.assertTrue(any("qualification evidence attestation bundle is missing or invalid" in error for error in errors))

    def test_external_verification_uses_the_trusted_attestation_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            for evidence in (root / "docs/evidence/desktop-qualification").glob("*.json"):
                evidence.with_name(evidence.name + ".intoto.jsonl").write_text("bundle\n", encoding="utf-8")
            with patch("scripts.desktop.validate_qualification_matrices.verify_attestation", return_value={"verified": True}) as verifier:
                errors = validate_matrices(root, verify_external=True, source_ref=SOURCE_REF, source_digest=SOURCE_DIGEST, attestation_policy=POLICY)
        self.assertEqual(errors, [])
        self.assertEqual(verifier.call_count, len(MATRIX_DOCS))
        subject, bundle, called_policy, called_source_ref = verifier.call_args_list[0].args
        self.assertTrue(str(subject).endswith(".json"))
        self.assertTrue(str(bundle).endswith(".json.intoto.jsonl"))
        self.assertEqual(called_policy, POLICY)
        self.assertEqual(called_source_ref, SOURCE_DIGEST)

    def test_external_verification_rejects_an_evidence_source_ref_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            evidence = root / "docs/evidence/desktop-qualification/ACCESSIBILITY_TEST_MATRIX.json"
            value = json.loads(evidence.read_text(encoding="utf-8"))
            value["source_ref"] = "refs/tags/other"
            evidence.write_text(json.dumps(value), encoding="utf-8")
            errors = validate_matrices(root, verify_external=True, source_ref=SOURCE_REF, source_digest=SOURCE_DIGEST, attestation_policy=POLICY)
        self.assertTrue(any("source_ref does not match protected ref" in error for error in errors))

    def test_rejects_a_noncanonical_evidence_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            matrix = root / "docs/desktop/06-design-system/ACCESSIBILITY_TEST_MATRIX.md"
            marker = json.loads(matrix.read_text(encoding="utf-8").splitlines()[1].partition(":")[2].strip())
            marker["evidence_ref"] = "docs/evidence/desktop-qualification/other.json"
            matrix.write_text("---\nqualification_evidence: " + json.dumps(marker) + "\n---\n| Check | Automated | Manual |\nNo P0/P1 accessibility defect\n", encoding="utf-8")
            errors = validate_matrices(root)
        self.assertTrue(any("qualification evidence_ref must be canonical" in error for error in errors))

    def test_rejects_invented_result_row_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            evidence = root / "docs/evidence/desktop-qualification/ACCESSIBILITY_TEST_MATRIX.json"
            value = json.loads(evidence.read_text(encoding="utf-8"))
            value["results"][0]["row_id"] = "P0-invented"
            evidence.write_text(json.dumps(value), encoding="utf-8")
            errors = validate_matrices(root)
        self.assertTrue(any("results must be exactly P0 and P1" in error for error in errors))

    def test_rejects_a_matrix_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            evidence = root / "docs/evidence/desktop-qualification/ACCESSIBILITY_TEST_MATRIX.json"
            value = json.loads(evidence.read_text(encoding="utf-8"))
            value["matrix_sha256"] = "0" * 64
            evidence.write_text(json.dumps(value), encoding="utf-8")
            errors = validate_matrices(root)
        self.assertTrue(any("matrix_sha256 mismatch" in error for error in errors))

    def test_rejects_duplicate_keys_in_qualification_marker(self):
        marker = '{"schema_version":"desktop-qualification-matrix.v1","disposition":"blocked","disposition":"verified","evidence_ref":null,"p0_p1_disposition":"blocked"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_matrix_tree(root, marker)
            errors = validate_matrices(root)
        self.assertTrue(any("invalid qualification_evidence marker" in error for error in errors))

    def test_rejects_duplicate_keys_in_evidence_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_verified_canonical_tree(root)
            evidence = root / "docs/evidence/desktop-qualification/ACCESSIBILITY_TEST_MATRIX.json"
            raw = evidence.read_text(encoding="utf-8").replace('"producer":"protected-runner"', '"producer":"protected-runner","producer":"forged"')
            evidence.write_text(raw, encoding="utf-8")
            errors = validate_matrices(root)
        self.assertTrue(any("qualification evidence is not structured JSON" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
