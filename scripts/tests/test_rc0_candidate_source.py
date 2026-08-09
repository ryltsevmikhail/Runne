import hashlib
import importlib
import subprocess
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
