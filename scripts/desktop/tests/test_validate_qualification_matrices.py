import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.validate_qualification_matrices import validate_matrices


ROOT = Path(__file__).resolve().parents[3]
MATRIX_DOCS = {
    "docs/desktop/06-design-system/ACCESSIBILITY_TEST_MATRIX.md": ("| Check | Automated | Manual |", "No P0/P1 accessibility defect"),
    "docs/desktop/06-design-system/LOCALIZATION.md": ("v1 product locales: Russian and English.", "bidi isolation"),
    "docs/desktop/07-testing/SECURITY_ABUSE_CASES.md": ("| ID | Attack | Expected result |", "| SA-018 |"),
    "docs/desktop/03-desktop/ERROR_AND_DEGRADED_STATE_MATRIX.md": ("| Condition | Visible state | Allowed | Primary recovery |", "no duplicate command"),
}


def _write_matrix_tree(root: Path, marker: str) -> None:
    for relative, body_markers in MATRIX_DOCS.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n".join(body_markers)
        path.write_text(
            "---\nqualification_evidence: " + marker + "\n---\n" + body + "\n",
            encoding="utf-8",
        )


class QualificationMatrixValidationTest(unittest.TestCase):
    def test_rejects_a_matrix_without_a_machine_readable_marker(self):
        """Human prose alone must not establish qualification disposition."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            access = root / "docs/desktop/06-design-system/ACCESSIBILITY_TEST_MATRIX.md"
            access.parent.mkdir(parents=True, exist_ok=True)
            access.write_text("# Accessibility Test Matrix\n| Check | Automated | Manual |\nNo P0/P1 accessibility defect\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate_qualification_matrices.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("ACCESSIBILITY_TEST_MATRIX.md: invalid qualification_evidence marker", result.stdout)

    def test_rejects_an_accepted_p0_p1_disposition(self):
        """Accepted or waived P0/P1 rows cannot be represented as qualification evidence."""
        marker = '{"schema_version":"desktop-qualification-matrix.v1","disposition":"blocked","evidence_ref":null,"p0_p1_disposition":"accepted"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_matrix_tree(root, marker)
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate_qualification_matrices.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("forbidden P0/P1 disposition accepted", result.stdout)

    def test_rejects_verified_disposition_without_evidence(self):
        """A verified marker must point to an independently present evidence file."""
        marker = '{"schema_version":"desktop-qualification-matrix.v1","disposition":"verified","evidence_ref":null,"p0_p1_disposition":"verified"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_matrix_tree(root, marker)
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate_qualification_matrices.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("verified disposition requires evidence_ref", result.stdout)

    def test_rejects_verified_disposition_with_missing_evidence_file(self):
        """A claimed evidence path must resolve to an independently present file."""
        marker = '{"schema_version":"desktop-qualification-matrix.v1","disposition":"verified","evidence_ref":"docs/evidence/desktop-qualification/ACCESSIBILITY_TEST_MATRIX.json","p0_p1_disposition":"verified"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_matrix_tree(root, marker)
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate_qualification_matrices.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("qualification evidence_ref is missing", result.stdout)

    def test_rejects_verified_matrix_with_unverified_p0_p1_evidence(self):
        """A verified matrix cannot retain a blocked or unverified P0/P1 marker."""
        marker = '{"schema_version":"desktop-qualification-matrix.v1","disposition":"verified","evidence_ref":"evidence.json","p0_p1_disposition":"unverified"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_matrix_tree(root, marker)
            (root / "evidence.json").write_text('{"schema_version":"desktop-qualification-evidence.v1"}', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate_qualification_matrices.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("verified qualification requires verified P0/P1 disposition", result.stdout)

    def test_rejects_a_matrix_self_reference_as_verified_evidence(self):
        """A matrix cannot certify itself through evidence_ref."""
        marker = '{"schema_version":"desktop-qualification-matrix.v1","disposition":"verified","evidence_ref":"docs/desktop/06-design-system/ACCESSIBILITY_TEST_MATRIX.md","p0_p1_disposition":"verified"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_matrix_tree(root, marker)
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate_qualification_matrices.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("qualification evidence_ref must be distinct from matrix", result.stdout)

    def test_rejects_irrelevant_json_as_verified_evidence(self):
        """An arbitrary JSON document cannot establish P0/P1 qualification."""
        marker = '{"schema_version":"desktop-qualification-matrix.v1","disposition":"verified","evidence_ref":"docs/evidence/desktop-qualification/ACCESSIBILITY_TEST_MATRIX.json","p0_p1_disposition":"verified"}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_matrix_tree(root, marker)
            evidence = root / "docs/evidence/desktop-qualification/ACCESSIBILITY_TEST_MATRIX.json"
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text('{"schema_version":"unrelated.v1","results":[{"ok":true}]}', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate_qualification_matrices.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("qualification evidence has invalid schema", result.stdout)

if __name__ == "__main__":
    unittest.main()
