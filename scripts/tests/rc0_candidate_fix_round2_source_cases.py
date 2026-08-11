import os
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.tests.test_rc0_candidate_source import (
    FIXTURES,
    PINNED,
    ROOT,
    Rc0CandidateSourceTests,
    candidate_source,
    git,
)


class Rc0CandidateSourceFixRound2Tests(unittest.TestCase):
    def make_linked_repo(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT.parent)
        self.addCleanup(temporary.cleanup)
        container = Path(temporary.name)
        main = container / "main"
        main.mkdir()
        git(main, "init", "-q")
        git(main, "config", "user.name", "RC0 Fixture")
        git(main, "config", "user.email", "rc0-fixture@example.invalid")
        (main / "README").write_text("root\n", encoding="utf-8")
        git(main, "add", "README")
        git(main, "commit", "-qm", "root")
        (main / "upstream").mkdir()
        git(main / "upstream", "clone", "-q", str(ROOT / "upstream/opencode"), "opencode")
        expected = (FIXTURES / "gitmodules.expected").read_bytes()
        (main / ".gitmodules").write_bytes(expected)
        git(main, "add", ".gitmodules", "upstream/opencode")
        git(main, "commit", "-qm", "source")
        git(main, "remote", "add", "origin", "https://github.com/Ryltsevmg/gocode")
        linked = container / "linked"
        git(main, "worktree", "add", "-q", "--detach", str(linked), "HEAD")
        nested = linked / "upstream/opencode"
        if nested.exists():
            nested.rmdir()
        git(linked / "upstream", "clone", "-q", str(ROOT / "upstream/opencode"), "opencode")
        git(linked, "submodule", "absorbgitdirs", "upstream/opencode")
        return linked, expected

    def expectation(self, repo, expected):
        source = candidate_source()
        head = git(repo, "rev-parse", "HEAD").strip()
        return source.FixtureSourceExpectation(
            candidate_source_revision=head,
            captured_origin_main_revision=head,
            raw_tree_oid=git(repo, "rev-parse", "HEAD^{tree}").strip(),
            raw_gitmodules_sha256=__import__("hashlib").sha256(expected).hexdigest(),
            raw_opencode_gitlink_revision=PINNED,
            expected_gitmodules_bytes=expected,
        )

    def test_linked_worktree_uses_retained_gitdir_and_common_dir(self):
        source = candidate_source()
        repo, expected = self.make_linked_repo()
        result = source.validate_fixture_source(repo, self.expectation(repo, expected))
        self.assertEqual(result.status, "FIXTURE_LOCAL_INPUTS_SATISFIED")

    def test_linked_worktree_rejects_commondir_and_decoy_object_controls(self):
        source = candidate_source()
        for mutation in ("commondir", "gitdir-alternates", "common-alternates"):
            repo, expected = self.make_linked_repo()
            gitdir = Path(git(repo, "rev-parse", "--absolute-git-dir").strip())
            common = Path(git(repo, "rev-parse", "--git-common-dir").strip())
            if mutation == "commondir":
                decoy = repo.parent / "decoy-common"
                shutil.copytree(common, decoy)
                relative = os.path.relpath(decoy, gitdir)
                (gitdir / "commondir").write_text(relative + "\n", encoding="utf-8")
            else:
                objects = (gitdir if mutation == "gitdir-alternates" else common) / "objects"
                (objects / "info").mkdir(parents=True, exist_ok=True)
                (objects / "info/alternates").write_text("/tmp/decoy\n", encoding="utf-8")
            with self.subTest(mutation=mutation):
                result = source.validate_fixture_source(repo, self.expectation(repo, expected))
                self.assertEqual(result.status, "BLOCKED")

    def test_final_snapshot_detects_gitfile_and_submodule_entry_replacement(self):
        source = candidate_source()
        for mutation in (
            "root", "gitfile", "gitdir", "common-dir", "submodule-config",
            "submodule-entry",
        ):
            repo, expected = self.make_linked_repo()

            def replace(stage, captured, selected=mutation):
                if stage != "before-final-recheck":
                    return
                if selected == "root":
                    moved = captured.with_name(captured.name + ".old")
                    captured.rename(moved)
                    shutil.copytree(moved, captured)
                elif selected == "gitfile":
                    data = (captured / ".git").read_bytes()
                    replacement = captured / ".git.new"
                    replacement.write_bytes(data)
                    replacement.replace(captured / ".git")
                elif selected in ("gitdir", "common-dir"):
                    argument = "--absolute-git-dir" if selected == "gitdir" else "--git-common-dir"
                    admin = Path(git(captured, "rev-parse", argument).strip())
                    moved = admin.with_name(admin.name + ".old")
                    admin.rename(moved)
                    shutil.copytree(moved, admin)
                elif selected == "submodule-config":
                    common = Path(
                        git(captured / "upstream/opencode", "rev-parse", "--git-common-dir").strip()
                    )
                    config = common / "config"
                    replacement = common / "config.new"
                    replacement.write_bytes(config.read_bytes())
                    replacement.replace(config)
                else:
                    nested = captured / "upstream/opencode"
                    moved = captured / "upstream/opencode.old"
                    nested.rename(moved)
                    git(captured / "upstream", "clone", "-q", str(ROOT / "upstream/opencode"), "opencode")

            with self.subTest(mutation=mutation):
                result = source.validate_fixture_source(
                    repo, self.expectation(repo, expected), mutation_hook=replace
                )
                self.assertEqual(result.blocked_reason, "SOURCE_SNAPSHOT_CHANGED")


if __name__ == "__main__":
    unittest.main()
