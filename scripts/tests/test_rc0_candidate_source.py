import hashlib
import importlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts/tests/fixtures/rc0_candidate"
PINNED = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"


def candidate_source():
    try:
        return importlib.import_module("scripts.rc0_candidate.source")
    except ModuleNotFoundError as error:
        raise AssertionError("candidate source capture is absent") from error


def git(repo, *args, text=True):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=text
    ).stdout


class Rc0CandidateSourceTests(unittest.TestCase):
    def make_repo(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT.parent)
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name)
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "RC0 Fixture")
        git(repo, "config", "user.email", "rc0-fixture@example.invalid")
        (repo / "README").write_text("root\n", encoding="utf-8")
        git(repo, "add", "README")
        git(repo, "commit", "-qm", "root")
        (repo / "upstream").mkdir()
        git(repo / "upstream", "clone", "-q", str(ROOT / "upstream/opencode"), "opencode")
        expected = (FIXTURES / "gitmodules.expected").read_bytes()
        (repo / ".gitmodules").write_bytes(expected)
        git(repo, "add", ".gitmodules", "upstream/opencode")
        git(repo, "commit", "-qm", "source")
        git(repo, "remote", "add", "origin", "https://github.com/Ryltsevmg/gocode")
        return repo, expected

    def expectation(self, repo, expected):
        source = candidate_source()
        return source.FixtureSourceExpectation(
            candidate_source_revision=git(repo, "rev-parse", "HEAD").strip(),
            captured_origin_main_revision=git(repo, "rev-parse", "HEAD").strip(),
            raw_tree_oid=git(repo, "rev-parse", "HEAD^{tree}").strip(),
            raw_gitmodules_sha256=hashlib.sha256(expected).hexdigest(),
            raw_opencode_gitlink_revision=PINNED,
            expected_gitmodules_bytes=expected,
        )

    def test_dirty_or_non_single_parent_source_is_blocked(self):
        source = candidate_source()
        repo, expected = self.make_repo()
        valid = source.validate_fixture_source(repo, self.expectation(repo, expected))
        self.assertEqual(valid.status, "FIXTURE_LOCAL_INPUTS_SATISFIED")

        (repo / "README").write_text("dirty\n", encoding="utf-8")
        dirty = source.validate_fixture_source(repo, self.expectation(repo, expected))
        self.assertEqual((dirty.status, dirty.blocked_reason), ("BLOCKED", "SOURCE_DIRTY"))

        merged, expected = self.make_repo()
        git(merged, "checkout", "-qb", "side", "HEAD^")
        (merged / "side").write_text("side\n", encoding="utf-8")
        git(merged, "add", "side")
        git(merged, "commit", "-qm", "side")
        git(merged, "checkout", "-q", "master")
        (merged / "main").write_text("main\n", encoding="utf-8")
        git(merged, "add", "main")
        git(merged, "commit", "-qm", "main")
        git(merged, "merge", "--no-ff", "-qm", "merge", "side")
        history = source.validate_fixture_source(merged, self.expectation(merged, expected))
        self.assertEqual(history.blocked_reason, "SOURCE_HISTORY_INVALID")

    def test_rejects_noncanonical_url_and_gitlink_policy_mismatch(self):
        source = candidate_source()
        repo, expected = self.make_repo()
        git(repo, "remote", "set-url", "origin", "git@github.com:Ryltsevmg/gocode.git")
        remote = source.validate_fixture_source(repo, self.expectation(repo, expected))
        self.assertEqual(remote.blocked_reason, "SOURCE_REMOTE_IDENTITY_MISMATCH")

        repo, expected = self.make_repo()
        wrong = self.expectation(repo, expected)
        wrong = source.FixtureSourceExpectation(
            **{**wrong.__dict__, "raw_opencode_gitlink_revision": "1" * 40}
        )
        gitlink = source.validate_fixture_source(repo, wrong)
        self.assertEqual(gitlink.blocked_reason, "SOURCE_GITLINK_POLICY_MISMATCH")

        repo, expected = self.make_repo()
        wrong = self.expectation(repo, expected)
        wrong = source.FixtureSourceExpectation(
            **{**wrong.__dict__, "raw_gitmodules_sha256": "2" * 64}
        )
        modules = source.validate_fixture_source(repo, wrong)
        self.assertEqual(modules.blocked_reason, "SOURCE_GITMODULES_POLICY_MISMATCH")

        repo, _expected = self.make_repo()
        alternate = _expected.replace(b"anomalyco/opencode", b"example/alternate")
        (repo / ".gitmodules").write_bytes(alternate)
        git(repo, "add", ".gitmodules")
        git(repo, "commit", "-qm", "change module identity")
        self_chosen = source.validate_fixture_source(repo, self.expectation(repo, alternate))
        self.assertEqual(self_chosen.blocked_reason, "SOURCE_GITMODULES_POLICY_MISMATCH")

        repo, expected = self.make_repo()
        malformed = self.expectation(repo, expected)
        malformed = source.FixtureSourceExpectation(
            **{**malformed.__dict__, "expected_gitmodules_bytes": "not-bytes"}
        )
        malformed_result = source.validate_fixture_source(repo, malformed)
        self.assertEqual(malformed_result.blocked_reason, "SOURCE_GITMODULES_POLICY_MISMATCH")

    def test_production_capture_requires_external_approval(self):
        result = candidate_source().capture_current_source()
        self.assertEqual(
            (result.status, result.blocked_reason),
            ("BLOCKED", "EXTERNAL_SOURCE_CAPTURE_REQUIRES_APPROVAL"),
        )

    def test_rejects_dotdot_repository_alias(self):
        source = candidate_source()
        repo, expected = self.make_repo()
        alias = repo / ".." / repo.name
        result = source.validate_fixture_source(alias, self.expectation(repo, expected))
        self.assertEqual(result.blocked_reason, "SOURCE_PATH_UNSAFE")

    def test_ambient_git_and_path_redirectors_cannot_change_capture(self):
        source = candidate_source()
        repo, expected = self.make_repo()
        expected_capture = self.expectation(repo, expected)
        fake_dir = Path(tempfile.mkdtemp(dir=ROOT.parent))
        self.addCleanup(lambda: __import__("shutil").rmtree(fake_dir))
        fake_git = fake_dir / "git"
        fake_git.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
        fake_git.chmod(0o755)
        hostile = {
            "PATH": str(fake_dir), "GIT_DIR": "/hostile/git",
            "GIT_WORK_TREE": "/hostile/worktree", "GIT_INDEX_FILE": "/hostile/index",
            "GIT_OBJECT_DIRECTORY": "/hostile/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/hostile/alternates",
            "GIT_COMMON_DIR": "/hostile/common", "GIT_CONFIG": "/hostile/config",
            "GIT_CONFIG_GLOBAL": "/hostile/global", "GIT_CONFIG_SYSTEM": "/hostile/system",
            "GIT_CONFIG_NOSYSTEM": "0", "HOME": "/hostile/home",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/hostile/hooks", "GIT_CONFIG_PARAMETERS": "'alias.status=!false'",
        }
        with patch.dict(__import__("os").environ, hostile):
            result = source.validate_fixture_source(repo, expected_capture)
        self.assertEqual(result.status, "FIXTURE_LOCAL_INPUTS_SATISFIED")

    def test_rejects_config_rewrites_credentials_promisor_and_alternates(self):
        source = candidate_source()
        cases = (
            ("include.path", "/tmp/hostile-config"),
            ("includeIf.gitdir:/tmp/.path", "/tmp/hostile-config"),
            ("url.https://evil.invalid/.insteadOf", "https://github.com/"),
            ("url.https://evil.invalid/.pushInsteadOf", "https://github.com/"),
            ("credential.helper", "!false"), ("http.proxy", "https://proxy.invalid"),
            ("http.extraHeader", "Authorization: secret"),
            ("http.https://github.com/.extraHeader", "Authorization: secret"),
            ("http.https://github.com/.proxy", "https://proxy.invalid"),
            ("remote.origin.promisor", "true"),
            ("remote.origin.partialclonefilter", "blob:none"),
            ("core.hooksPath", "/tmp/hooks"), ("core.fsmonitor", "!false"),
            ("core.worktree", "."), ("extensions.worktreeConfig", "true"),
            ("core.excludesFile", "/tmp/excludes"), ("alias.status", "!false"),
        )
        for key, value in cases:
            repo, expected = self.make_repo()
            git(repo, "config", "--local", key, value)
            with self.subTest(key=key):
                result = source.validate_fixture_source(repo, self.expectation(repo, expected))
                self.assertEqual(result.blocked_reason, "SOURCE_GIT_CONFIG_UNSAFE")

        for name in ("alternates", "http-alternates"):
            repo, expected = self.make_repo()
            alternate = repo / ".git/objects/info" / name
            alternate.write_text(str(ROOT / ".git/objects") + "\n", encoding="utf-8")
            result = source.validate_fixture_source(repo, self.expectation(repo, expected))
            self.assertEqual(result.blocked_reason, "SOURCE_GIT_OBJECT_STORE_UNSAFE")

        repo, expected = self.make_repo()
        git(repo / "upstream/opencode", "config", "--local", "credential.helper", "!false")
        result = source.validate_fixture_source(repo, self.expectation(repo, expected))
        self.assertEqual(result.blocked_reason, "SOURCE_GIT_CONFIG_UNSAFE")

    def test_rejects_origin_url_credentials_query_fragment_and_encoding(self):
        source = candidate_source()
        for url in (
            "https://user:password@github.com/Ryltsevmg/gocode",
            "https://github.com/Ryltsevmg/gocode?access_token=x",
            "https://github.com/Ryltsevmg/gocode#signature=x",
            "https://user%3Apassword%40github.com/Ryltsevmg/gocode",
        ):
            repo, expected = self.make_repo()
            git(repo, "remote", "set-url", "origin", url)
            with self.subTest(url=url):
                result = source.validate_fixture_source(repo, self.expectation(repo, expected))
                self.assertEqual(result.blocked_reason, "SOURCE_REMOTE_IDENTITY_MISMATCH")

    def test_snapshot_recheck_blocks_head_status_origin_and_gitmodules_swaps(self):
        source = candidate_source()
        for mutation in ("head", "status", "origin", "gitmodules", "alternates"):
            repo, expected = self.make_repo()

            def mutate(stage, captured_repo, selected=mutation):
                if stage != "before-final-recheck":
                    return
                if selected == "head":
                    (captured_repo / "late").write_text("late\n", encoding="utf-8")
                    git(captured_repo, "add", "late")
                    git(captured_repo, "commit", "-qm", "late")
                elif selected == "status":
                    (captured_repo / "untracked").write_text("late\n", encoding="utf-8")
                elif selected == "origin":
                    git(captured_repo, "remote", "set-url", "origin", "https://github.com/Ryltsevmg/gocode.git")
                elif selected == "gitmodules":
                    replacement = captured_repo / ".gitmodules.replacement"
                    replacement.write_bytes(expected)
                    replacement.replace(captured_repo / ".gitmodules")
                else:
                    (captured_repo / ".git/objects/info/alternates").write_text(
                        "/tmp\n", encoding="utf-8"
                    )

            with self.subTest(mutation=mutation):
                result = source.validate_fixture_source(
                    repo, self.expectation(repo, expected), mutation_hook=mutate
                )
                self.assertEqual(result.status, "BLOCKED")
                if mutation != "alternates":
                    self.assertEqual(result.blocked_reason, "SOURCE_SNAPSHOT_CHANGED")


from scripts.tests.rc0_candidate_fix_round2_source_cases import (
    Rc0CandidateSourceFixRound2Tests,
)


if __name__ == "__main__":
    unittest.main()


from scripts.tests.rc0_candidate_v4_cases import Rc0CandidateSourceV4Tests
