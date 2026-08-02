import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "verify_secure_replay_evidence.py"


class VerifySecureReplayEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = pathlib.Path(self.temporary_directory.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Evidence Test")
        source = self.root / "crates" / "demo.rs"
        source.parent.mkdir()
        source.write_text("base\n", encoding="utf-8")
        self.git("add", "crates/demo.rs")
        self.git("commit", "-qm", "base")
        self.base_commit = self.output("rev-parse", "HEAD")
        source.write_text("historical\n", encoding="utf-8")
        self.evidence = self.root / "docs" / "evidence" / "record.json"
        self.evidence.parent.mkdir(parents=True)
        self.evidence.write_text("{}", encoding="utf-8")
        self.git("add", "crates/demo.rs", "docs/evidence/record.json")
        self.git("commit", "-qm", "historical snapshot")
        self.head_commit = self.output("rev-parse", "HEAD")
        self.write_evidence()

    def git(self, *arguments: str) -> None:
        subprocess.run(["git", "-C", str(self.root), *arguments], check=True)

    def output(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def changed_paths(self) -> list[tuple[str, str]]:
        output = subprocess.run(
            [
                "git", "-C", str(self.root), "diff", "--name-status", "-z",
                "--no-renames", self.base_commit, self.head_commit, "--",
            ],
            check=True,
            capture_output=True,
        ).stdout.split(b"\0")
        return list(zip(
            (value.decode() for value in output[0::2] if value),
            (value.decode() for value in output[1::2] if value),
        ))

    def write_evidence(self) -> None:
        entries = []
        for status, path in self.changed_paths():
            if path == "docs/evidence/record.json":
                continue
            entry = {"path": path, "status": "deleted", "sha256": None}
            if status != "D":
                blob = subprocess.run(
                    ["git", "-C", str(self.root), "show", f"{self.head_commit}:{path}"],
                    check=True,
                    capture_output=True,
                ).stdout
                entry = {
                    "path": path,
                    "status": "present",
                    "sha256": hashlib.sha256(blob).hexdigest(),
                }
            entries.append(entry)
        self.evidence.write_text(
            json.dumps(
                {"subject": {
                    "sourceBaseCommit": self.base_commit,
                    "sourceHeadCommit": self.head_commit,
                    "manifestAlgorithm": "git-tree-diff-sha256-v1",
                    "manifestSelfExcludedPath": "docs/evidence/record.json",
                    "changedFileManifest": entries,
                }},
            ),
            encoding="utf-8",
        )

    def record(self) -> dict:
        return json.loads(self.evidence.read_text(encoding="utf-8"))

    def save_record(self, record: dict) -> None:
        self.evidence.write_text(json.dumps(record), encoding="utf-8")

    def run_verifier(self, base: str | None = None, head: str | None = None):
        return subprocess.run(
            ["python3", str(SCRIPT_PATH), "--manifest", str(self.evidence),
             "--base", base or self.base_commit, "--head", head or self.head_commit],
            cwd=self.root,
            capture_output=True,
            text=True,
        )

    def test_accepts_historical_snapshot_after_later_commit_and_dirty_worktree(self) -> None:
        later = self.root / "later.txt"
        later.write_text("later\n", encoding="utf-8")
        self.git("add", "later.txt")
        self.git("commit", "-qm", "later unrelated commit")
        (self.root / "crates" / "demo.rs").write_text("dirty\n", encoding="utf-8")

        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("evidence manifest verified", result.stdout)

    def test_rejects_wrong_head_hash_disposition_or_unlisted_path(self) -> None:
        (self.root / "later.txt").write_text("later\n", encoding="utf-8")
        self.git("add", "later.txt")
        self.git("commit", "-qm", "later unrelated commit")
        wrong_head = self.output("rev-parse", "HEAD")
        result = self.run_verifier(head=wrong_head)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source head", result.stderr)

        record = self.record()
        record["subject"]["changedFileManifest"][0]["sha256"] = "0" * 64
        self.save_record(record)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)

        self.write_evidence()
        record = self.record()
        record["subject"]["changedFileManifest"][0]["status"] = "deleted"
        record["subject"]["changedFileManifest"][0]["sha256"] = None
        self.save_record(record)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected deleted", result.stderr)

        self.write_evidence()
        record = self.record()
        record["subject"]["changedFileManifest"].pop()
        self.save_record(record)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unlisted changed paths", result.stderr)

    def test_rejects_symlink_unsafe_and_nonimmutable_references(self) -> None:
        self.evidence.unlink()
        self.evidence.symlink_to("missing.json")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular non-symlink", result.stderr)
        self.evidence.unlink()
        self.write_evidence()

        record = self.record()
        record["subject"]["changedFileManifest"][0]["path"] = "../unsafe"
        self.save_record(record)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("safe repository-relative", result.stderr)

        self.write_evidence()
        for base, head in (("HEAD", self.head_commit), (self.base_commit[:8], self.head_commit),
                           (self.base_commit, "HEAD"), (self.base_commit, self.head_commit[:8])):
            result = self.run_verifier(base, head)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("full lowercase SHA-1", result.stderr)


if __name__ == "__main__":
    unittest.main()
