"""Regression tests for the fail-closed embedded Local Engine manifest."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_embedded_source",
    ROOT / "scripts/local-engine/verify-embedded-source.py",
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class VerifyEmbeddedSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        (self.root / "local-engine").mkdir()
        (self.root / "local-engine/a.rs").write_text("fn a() {}\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "local-engine"], cwd=self.root, check=True)
        self.manifest = self.root / "manifest.json"
        self._write_valid_manifest()

    def _write_valid_manifest(self) -> None:
        paths = VERIFIER.embedded_paths(self.root)
        self.manifest.write_text(
            json.dumps(
                {
                    "schema": "runne-local-engine-import.v1",
                    "embedded_file_count": len(paths),
                    "embedded_tree_sha256": VERIFIER.embedded_digest(self.root, paths),
                }
            ),
            encoding="utf-8",
        )

    def test_accepts_exact_tracked_tree(self) -> None:
        self.assertEqual(
            VERIFIER.verify(self.root, self.manifest)["embedded_file_count"], 1
        )

    def test_rejects_modified_tracked_file(self) -> None:
        (self.root / "local-engine/a.rs").write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest"):
            VERIFIER.verify(self.root, self.manifest)

    def test_rejects_added_tracked_file(self) -> None:
        (self.root / "local-engine/b.rs").write_text("fn b() {}\n", encoding="utf-8")
        subprocess.run(["git", "add", "local-engine/b.rs"], cwd=self.root, check=True)
        with self.assertRaisesRegex(ValueError, "count"):
            VERIFIER.verify(self.root, self.manifest)

    def test_rejects_malformed_manifest(self) -> None:
        self.manifest.write_text("{", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            VERIFIER.verify(self.root, self.manifest)


if __name__ == "__main__":
    unittest.main()
