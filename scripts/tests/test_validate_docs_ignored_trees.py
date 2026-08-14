"""Regression coverage for ignored generated and scratch documentation scan trees."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


from validate_docs_parts.repository_walk import _superpowers_path, walk_repository_files


class ValidateDocsIgnoredTreesTests(unittest.TestCase):
    def test_backslash_relative_path_is_canonicalized_for_git_comparison(self):
        self.assertTrue(_superpowers_path(r".superpowers\tracked.md"))

    def test_tracked_superpowers_file_is_scanned_while_ignored_paths_are_not(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".gitignore").write_text(".superpowers/\ntarget/\ntarget-*/\n", encoding="utf-8")
            tracked = repo / ".superpowers" / "tracked.md"
            scratch = repo / ".superpowers" / "scratch.md"
            target = repo / "target" / "generated-empty"
            named_target = repo / "target-docs-gate" / "generated-empty"
            source = repo / "source-empty"
            for path in (tracked, scratch, target, named_target, source):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", ".gitignore", "source-empty", "-f", ".superpowers/tracked.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
            for path in (scratch, target, named_target):
                self.assertEqual(subprocess.run(["git", "-C", str(repo), "check-ignore", "-q", "--", str(path.relative_to(repo))]).returncode, 0)
            found = {Path(path).relative_to(repo).as_posix() for path in walk_repository_files(str(repo), str(repo))}
            self.assertIn(".superpowers/tracked.md", found)
            self.assertNotIn(".superpowers/scratch.md", found)
            self.assertNotIn("target/generated-empty", found)
            self.assertNotIn("target-docs-gate/generated-empty", found)
            self.assertIn("source-empty", found)

    def test_ignored_generated_and_scratch_empty_files_are_not_reported(self):
        token = str(os.getpid())
        target_root = ROOT / "target"
        target_root_created = not target_root.exists()
        target_dir = target_root / f"docs-gate-{token}"
        generated_dir = ROOT / f"target-docs-gate-{token}"
        scratch_dir = ROOT / ".superpowers" / f"docs-gate-{token}"
        source_file = ROOT / f"docs-gate-empty-source-{token}"
        target_file = target_dir / "generated-empty"
        generated_file = generated_dir / "generated-empty"
        scratch_file = scratch_dir / "scratch-empty"
        for directory in (target_dir, generated_dir, scratch_dir):
            directory.mkdir(parents=True)
        for path in (target_file, generated_file, scratch_file, source_file):
            path.touch()
        self.addCleanup(source_file.unlink)
        if target_root_created:
            self.addCleanup(target_root.rmdir)
        self.addCleanup(target_dir.rmdir)
        self.addCleanup(target_file.unlink)
        self.addCleanup(generated_dir.rmdir)
        self.addCleanup(generated_file.unlink)
        self.addCleanup(scratch_dir.rmdir)
        self.addCleanup(scratch_file.unlink)

        for path in (target_file, generated_file, scratch_file):
            self.assertEqual(
                subprocess.run(
                    ["git", "check-ignore", "-q", "--", str(path.relative_to(ROOT))],
                    cwd=ROOT,
                ).returncode,
                0,
            )

        result = subprocess.run(
            [sys.executable, "scripts/validate-docs.py"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        self.assertIn(f"Empty file: {source_file.name}", result.stdout)
        self.assertNotIn(str(target_file.relative_to(ROOT)), result.stdout)
        self.assertNotIn(str(generated_file.relative_to(ROOT)), result.stdout)
        self.assertNotIn(str(scratch_file.relative_to(ROOT)), result.stdout)


if __name__ == "__main__":
    unittest.main()
