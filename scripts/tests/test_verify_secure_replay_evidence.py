import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT_PATH = (
    pathlib.Path(__file__).parents[1] / "verify_secure_replay_evidence.py"
)


class VerifySecureReplayEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = pathlib.Path(self.temporary_directory.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Evidence Test"],
            check=True,
        )
        source = self.root / "crates" / "demo.rs"
        source.parent.mkdir()
        source.write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "crates/demo.rs"], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "base"],
            check=True,
        )
        self.base_commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        source.write_text("changed\n", encoding="utf-8")
        self.evidence = self.root / "docs" / "evidence" / "record.json"
        self.evidence.parent.mkdir(parents=True)
        self.write_evidence(source)

    def write_evidence(self, source: pathlib.Path) -> None:
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.evidence.write_text(
            json.dumps(
                {
                    "subject": {
                        "sourceBaseCommit": self.base_commit,
                        "manifestSelfExcludedPath": "docs/evidence/record.json",
                        "changedFileManifest": [
                            {
                                "path": "crates/demo.rs",
                                "status": "present",
                                "sha256": digest,
                            }
                        ],
                    }
                }
            ),
            encoding="utf-8",
        )

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT_PATH),
                "--manifest",
                str(self.evidence),
                "--base",
                self.base_commit[:8],
                "--head",
                "HEAD",
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
        )

    def declare_source_deleted(self) -> None:
        record = json.loads(self.evidence.read_text(encoding="utf-8"))
        record["subject"]["changedFileManifest"] = [
            {
                "path": "crates/demo.rs",
                "status": "deleted",
                "sha256": None,
            }
        ]
        self.evidence.write_text(json.dumps(record), encoding="utf-8")

    def test_accepts_the_exact_exhaustive_changed_file_manifest(self) -> None:
        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("evidence manifest verified", result.stdout)

    def test_accepts_explicit_manifest_base_and_head_snapshot(self) -> None:
        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("evidence manifest verified", result.stdout)

    def test_rejects_an_unlisted_untracked_implementation_file(self) -> None:
        extra = self.root / "apps" / "extra.ts"
        extra.parent.mkdir()
        extra.write_text("export {}\n", encoding="utf-8")

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unlisted changed paths: apps/extra.ts", result.stderr)

    def test_rejects_an_unlisted_tracked_change(self) -> None:
        extra = self.root / "scripts" / "extra.sh"
        extra.parent.mkdir()
        extra.write_text("#!/bin/sh\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "scripts/extra.sh"], check=True)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unlisted changed paths: scripts/extra.sh", result.stderr)

    def test_rejects_changed_bytes_at_a_listed_path(self) -> None:
        source = self.root / "crates" / "demo.rs"
        source.write_text("changed again\n", encoding="utf-8")

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch for: crates/demo.rs", result.stderr)

    def test_accepts_a_tracked_file_declared_and_actually_deleted(self) -> None:
        source = self.root / "crates" / "demo.rs"
        source.unlink()
        self.declare_source_deleted()

        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_a_dangling_symlink_declared_as_deleted(self) -> None:
        source = self.root / "crates" / "demo.rs"
        source.unlink()
        source.symlink_to("missing.rs")
        self.declare_source_deleted()

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected deleted path", result.stderr)


if __name__ == "__main__":
    unittest.main()
