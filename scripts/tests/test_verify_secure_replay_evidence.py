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
        self.run_git("init", "-q")
        self.run_git("config", "user.email", "test@example.invalid")
        self.run_git("config", "user.name", "Evidence Test")
        self.source = self.root / "crates" / "demo.rs"
        self.deleted = self.root / "crates" / "deleted.rs"
        self.source.parent.mkdir()
        self.source.write_text("base\n", encoding="utf-8")
        self.deleted.write_text("deleted base\n", encoding="utf-8")
        self.run_git("add", "crates")
        self.run_git("commit", "-qm", "base")
        self.base_commit = self.git_output("rev-parse", "HEAD")

        self.source.write_text("snapshot\n", encoding="utf-8")
        self.deleted.unlink()
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "recorded snapshot")
        self.snapshot_commit = self.git_output("rev-parse", "HEAD")
        self.evidence = self.root / "docs" / "evidence" / "record.json"
        self.evidence.parent.mkdir(parents=True)
        self.write_evidence()

        later = self.root / "scripts" / "later.sh"
        later.parent.mkdir()
        later.write_text("#!/bin/sh\n", encoding="utf-8")
        self.run_git("add", "scripts/later.sh")
        self.run_git("commit", "-qm", "later commit")
        self.later_commit = self.git_output("rev-parse", "HEAD")
        self.source.write_text("worktree drift\n", encoding="utf-8")
        extra = self.root / "apps" / "untracked.ts"
        extra.parent.mkdir()
        extra.write_text("export {}\n", encoding="utf-8")

    def run_git(self, *arguments: str) -> None:
        subprocess.run(["git", "-C", str(self.root), *arguments], check=True)

    def git_output(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def write_evidence(self) -> None:
        digest = hashlib.sha256(b"snapshot\n").hexdigest()
        self.evidence.write_text(
            json.dumps(
                {
                    "subject": {
                        "sourceBaseCommit": self.base_commit,
                        "sourceHeadCommit": self.snapshot_commit,
                        "manifestSelfExcludedPath": "docs/evidence/record.json",
                        "changedFileManifest": [
                            {
                                "path": "crates/demo.rs",
                                "status": "present",
                                "sha256": digest,
                            },
                            {
                                "path": "crates/deleted.rs",
                                "status": "deleted",
                                "sha256": None,
                            },
                        ],
                    }
                }
            ),
            encoding="utf-8",
        )

    def record(self) -> dict[str, object]:
        return json.loads(self.evidence.read_text(encoding="utf-8"))

    def save_record(self, record: dict[str, object]) -> None:
        self.evidence.write_text(json.dumps(record), encoding="utf-8")

    def append_present_entry(
        self, record: dict[str, object], path: str, contents: bytes
    ) -> None:
        record["subject"]["changedFileManifest"].append(
            {"path": path, "status": "present", "sha256": hashlib.sha256(contents).hexdigest()}
        )

    def record_later_commit_path(self, record: dict[str, object]) -> None:
        self.append_present_entry(record, "scripts/later.sh", b"#!/bin/sh\n")

    def run_verifier(
        self, head: str | None = None, base: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT_PATH),
                "--manifest",
                str(self.evidence),
                "--base",
                base or self.base_commit,
                "--head",
                head or self.snapshot_commit,
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
        )

    def test_accepts_immutable_snapshot_after_later_commits_and_worktree_drift(self) -> None:
        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("evidence manifest verified", result.stdout)

    def test_accepts_deleted_disposition_from_the_recorded_diff(self) -> None:
        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_a_tampered_recorded_blob_digest(self) -> None:
        record = self.record()
        record["subject"]["changedFileManifest"][0]["sha256"] = "0" * 64
        self.save_record(record)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch for: crates/demo.rs", result.stderr)

    def test_rejects_manifest_head_that_does_not_match_the_cli_snapshot(self) -> None:
        result = self.run_verifier(head=self.later_commit)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest source head commit does not match --head", result.stderr)

    def test_rejects_manifest_base_that_does_not_match_the_cli_snapshot(self) -> None:
        result = self.run_verifier(base=self.snapshot_commit)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest source base commit does not match --base", result.stderr)

    def test_rejects_a_recorded_snapshot_unrelated_to_current_head(self) -> None:
        empty_tree = subprocess.run(
            ["git", "-C", str(self.root), "mktree"],
            check=True,
            input="",
            capture_output=True,
            text=True,
        ).stdout.strip()
        unrelated = subprocess.run(
            ["git", "-C", str(self.root), "commit-tree", empty_tree, "-m", "unrelated"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.run_git("update-ref", "HEAD", unrelated)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not an ancestor of the current checkout HEAD", result.stderr)

    def test_rejects_duplicate_manifest_entries(self) -> None:
        record = self.record()
        entries = record["subject"]["changedFileManifest"]
        entries.append(entries[0].copy())
        self.save_record(record)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate manifest path", result.stderr)

    def test_rejects_unsafe_manifest_paths(self) -> None:
        record = self.record()
        record["subject"]["changedFileManifest"][0]["path"] = "../demo.rs"
        self.save_record(record)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a safe repository-relative path", result.stderr)

    def test_rejects_malformed_manifest_hashes(self) -> None:
        record = self.record()
        record["subject"]["changedFileManifest"][0]["sha256"] = "not-a-hash"
        self.save_record(record)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid SHA-256 for: crates/demo.rs", result.stderr)

    def test_rejects_an_unlisted_recorded_snapshot_path(self) -> None:
        record = self.record()
        record["subject"]["changedFileManifest"].pop(0)
        self.save_record(record)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unlisted changed paths: crates/demo.rs", result.stderr)

    def test_rejects_a_stale_recorded_snapshot_path(self) -> None:
        record = self.record()
        self.append_present_entry(record, "crates/stale.rs", b"stale\n")
        self.save_record(record)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale manifest paths: crates/stale.rs", result.stderr)

    def test_rejects_a_base_that_is_not_an_ancestor_of_recorded_head(self) -> None:
        record = self.record()
        record["subject"]["sourceBaseCommit"] = self.later_commit
        self.save_record(record)

        result = self.run_verifier(base=self.later_commit)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source base commit is not an ancestor of --head", result.stderr)

    def test_rejects_an_unresolvable_recorded_head_reference(self) -> None:
        result = self.run_verifier(head="0" * 40)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid Git commit reference", result.stderr)

    def test_rejects_a_present_symlink_from_the_recorded_tree(self) -> None:
        link_target_blob = subprocess.run(
            ["git", "-C", str(self.root), "hash-object", "-w", "--stdin"],
            check=True,
            input=b"demo.rs",
            capture_output=True,
        ).stdout.decode().strip()
        self.run_git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{link_target_blob},crates/link",
        )
        self.run_git("commit", "-qm", "recorded symlink")
        symlink_head = self.git_output("rev-parse", "HEAD")
        record = self.record()
        record["subject"]["sourceHeadCommit"] = symlink_head
        self.record_later_commit_path(record)
        self.append_present_entry(record, "crates/link", b"demo.rs")
        self.save_record(record)

        result = self.run_verifier(head=symlink_head)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recorded manifest path is not a regular file: crates/link", result.stderr)

    def test_rejects_a_present_gitlink_from_the_recorded_tree(self) -> None:
        self.run_git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.snapshot_commit},crates/submodule",
        )
        self.run_git("commit", "-qm", "recorded gitlink")
        gitlink_head = self.git_output("rev-parse", "HEAD")
        record = self.record()
        record["subject"]["sourceHeadCommit"] = gitlink_head
        self.record_later_commit_path(record)
        self.append_present_entry(record, "crates/submodule", b"not a blob")
        self.save_record(record)

        result = self.run_verifier(head=gitlink_head)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "recorded manifest path is not a regular file: crates/submodule",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
