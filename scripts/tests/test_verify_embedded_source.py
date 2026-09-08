"""Regression tests for fail-closed Local Engine provenance verification."""

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_embedded_source", ROOT / "scripts/local-engine/verify-embedded-source.py"
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
        self.upstream = self.root / "upstream.json"
        self.files = [
            {
                "path": "a.rs",
                "mode": "100644",
                "sha256": hashlib.sha256((self.root / "local-engine/a.rs").read_bytes()).hexdigest(),
            }
        ]
        self._write_valid_manifests()

    def _write_valid_manifests(self, **overrides: object) -> None:
        upstream = {
            "schema": "runne-local-engine-upstream-tree.v1",
            "upstream_repository": "example/local-engine",
            "upstream_commit": "a" * 40,
            "file_count": len(self.files),
            "tree_sha256": VERIFIER.inventory_digest(self.files),
            "files": self.files,
        }
        self.upstream.write_text(json.dumps(upstream), encoding="utf-8")
        paths = VERIFIER.embedded_paths(self.root)
        payload = {
            "schema": "runne-local-engine-import.v2",
            "upstream_repository": upstream["upstream_repository"],
            "upstream_commit": upstream["upstream_commit"],
            "upstream_file_count": len(self.files),
            "upstream_tree_manifest": self.upstream.name,
            "upstream_tree_sha256": upstream["tree_sha256"],
            "embedded_file_count": len(paths),
            "embedded_tree_sha256": VERIFIER.embedded_digest(self.root, paths),
            "modified_after_import": [],
            "added_after_import": [],
            "missing_after_import": [],
        }
        payload.update(overrides)
        self.manifest.write_text(json.dumps(payload), encoding="utf-8")

    def test_accepts_exact_tracked_tree(self) -> None:
        self.assertEqual(VERIFIER.verify(self.root, self.manifest)["embedded_file_count"], 1)

    def test_rejects_modified_tracked_file(self) -> None:
        (self.root / "local-engine/a.rs").write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest"):
            VERIFIER.verify(self.root, self.manifest)

    def test_rejects_added_tracked_file(self) -> None:
        (self.root / "local-engine/b.rs").write_text("fn b() {}\n", encoding="utf-8")
        subprocess.run(["git", "add", "local-engine/b.rs"], cwd=self.root, check=True)
        with self.assertRaisesRegex(ValueError, "count"):
            VERIFIER.verify(self.root, self.manifest)

    def test_rejects_incomplete_modified_classification(self) -> None:
        (self.root / "local-engine/a.rs").write_text("split module\n", encoding="utf-8")
        self._write_valid_manifests(modified_after_import=[])
        with self.assertRaisesRegex(ValueError, "classifications"):
            VERIFIER.verify(self.root, self.manifest)

    def test_rejects_tracked_symlink_to_outside_local_engine(self) -> None:
        outside = self.root / "outside.rs"
        outside.write_text("outside\n", encoding="utf-8")
        embedded = self.root / "local-engine/a.rs"
        embedded.unlink()
        embedded.symlink_to(outside.name)
        with self.assertRaisesRegex(ValueError, "regular file"):
            VERIFIER.verify(self.root, self.manifest)

    def test_rejects_symlinked_upstream_tree_manifest(self) -> None:
        outside = self.root / "outside.json"
        outside.write_bytes(self.upstream.read_bytes())
        self.upstream.unlink()
        self.upstream.symlink_to(outside.name)
        with self.assertRaisesRegex(ValueError, "regular file"):
            VERIFIER.verify(self.root, self.manifest)

    def test_rejects_malformed_manifest(self) -> None:
        self.manifest.write_text("{", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            VERIFIER.verify(self.root, self.manifest)


if __name__ == "__main__":
    unittest.main()
