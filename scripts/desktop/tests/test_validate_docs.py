import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class DocsFrontMatterValidationTest(unittest.TestCase):
    def test_repository_docs_pass_strict_front_matter_gate(self):
        result = subprocess.run(
            [sys.executable, "scripts/desktop/validate-docs.py", "--strict"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_a_document_missing_required_front_matter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs/MISSING.md").write_text("---\ntitle: Missing\n---\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate-docs.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("MISSING.md: missing front matter field status", result.stdout)

    def test_rejects_a_stale_updated_date(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs/STALE.md").write_text(
                "---\ntitle: Stale\nstatus: draft\ndocument_type: reference\nsource_status: Target\ncreated: 2026-08-24\nupdated: 2026-08-23\n---\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "scripts/desktop/validate-docs.py", "--root", str(root)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("STALE.md: updated date is older than created date", result.stdout)

    def test_package_declares_the_docs_validation_gate(self):
        package = (ROOT / "package.json").read_text(encoding="utf-8")
        self.assertIn('"validate:docs": "python3 scripts/desktop/validate-docs.py --strict"', package)


if __name__ == "__main__":
    unittest.main()
