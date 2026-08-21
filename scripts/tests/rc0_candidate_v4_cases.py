import hashlib
import os
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCECRAFT = "https://git.sourcecraft.dev/ryltsevmg/gocode.git"
PINNED = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
PINNED_BLOB = ROOT / "upstream/opencode/packages/sdk/openapi.json"


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def git_bytes(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True
    ).stdout


def upstream_digest(repo):
    entries = git_bytes(repo, "ls-tree", "-r", "-z", "HEAD", "--", "upstream")
    digest = hashlib.sha256()
    count = 0
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        _mode, kind, oid = metadata.split(b" ")
        if kind == b"commit":
            continue
        if kind != b"blob":
            raise AssertionError("fixture upstream unexpectedly contains a non-blob")
        contents = git_bytes(repo, "cat-file", "blob", oid.decode())
        digest.update(path.removeprefix(b"upstream/"))
        digest.update(hashlib.sha256(contents).digest())
        count += 1
    return count, digest.hexdigest()


class Rc0CandidateEvidenceV4Tests(unittest.TestCase):
    def test_v4_embedded_upstream_records_construct_evidence(self):
        from scripts.tests.test_rc0_candidate_evidence import evidence_module, fixture_records_v4

        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            result = evidence.build_fixture_evidence(
                fixture_records_v4(), Path(output), Path(checkout)
            )
        self.assertEqual(set(result.blobs), set(evidence.EVIDENCE_FILES))

    def test_mixed_v3_v4_evidence_records_fail_closed(self):
        from scripts.tests.test_rc0_candidate_evidence import (
            evidence_module,
            fixture_records,
            fixture_records_v4,
        )

        evidence = evidence_module()
        records = fixture_records_v4()
        records["candidate-record.json"] = fixture_records()["candidate-record.json"]
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(records, Path(output), Path(checkout))

    def test_missing_json_record_profile_fails_closed(self):
        from scripts.tests.test_rc0_candidate_evidence import fixture_records_v4

        bindings = __import__("scripts.rc0_policy.bindings", fromlist=["unused"])
        model = __import__("scripts.rc0_policy.model", fromlist=["unused"])
        records = fixture_records_v4()
        records["checksums.txt"] = model.parse_checksums_text(records["checksums.txt"])
        records["source-gate-results.json"].pop("profile")
        self.assertIn("cross-record binding mismatch: profile", bindings.validate_record_bindings(records))


class Rc0CandidateSourceV4Tests(unittest.TestCase):
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
        embedded = repo / "upstream" / "opencode" / "packages" / "sdk"
        embedded.mkdir(parents=True)
        (embedded / "openapi.json").write_bytes(PINNED_BLOB.read_bytes())
        git(repo, "add", "README", "upstream")
        git(repo, "commit", "-qm", "source")
        git(repo, "remote", "add", "origin", SOURCECRAFT)
        return repo

    def expectation(self, source, repo):
        count, digest = upstream_digest(repo)
        return source.FixtureSourceExpectationV4(
            candidate_source_revision=git(repo, "rev-parse", "HEAD"),
            captured_origin_main_revision=git(repo, "rev-parse", "HEAD"),
            raw_tree_oid=git(repo, "rev-parse", "HEAD^{tree}"),
            upstream_tree_oid=git(repo, "rev-parse", "HEAD:upstream"),
            upstream_blob_count=count,
            upstream_content_digest=digest,
            opencode_source_sha=PINNED,
        )

    def test_v4_accepts_sourcecraft_embedded_upstream_and_rejects_mutations(self):
        source = __import__("scripts.rc0_candidate.source", fromlist=["unused"])
        repo = self.make_repo()
        expected = self.expectation(source, repo)
        result = source.validate_fixture_source_v4(repo, expected)
        self.assertEqual(result.status, "FIXTURE_LOCAL_INPUTS_SATISFIED")

        github = self.make_repo()
        git(github, "remote", "set-url", "origin", "https://github.com/Ryltsevmg/gocode.git")
        self.assertEqual(
            source.validate_fixture_source_v4(github, self.expectation(source, github)).blocked_reason,
            "SOURCE_REMOTE_IDENTITY_MISMATCH",
        )

        wrong = deepcopy(expected)
        wrong = source.FixtureSourceExpectationV4(
            **{**wrong.__dict__, "upstream_content_digest": "0" * 64}
        )
        self.assertEqual(
            source.validate_fixture_source_v4(repo, wrong).blocked_reason,
            "SOURCE_UPSTREAM_CONTENT_MISMATCH",
        )

        gitlink = self.make_repo()
        git(gitlink, "update-index", "--add", "--cacheinfo", f"160000,{git(gitlink, 'rev-parse', 'HEAD')},upstream/link")
        git(gitlink, "commit", "-qm", "gitlink")
        self.assertEqual(
            source.validate_fixture_source_v4(gitlink, self.expectation(source, gitlink)).blocked_reason,
            "SOURCE_UPSTREAM_GITLINK_FORBIDDEN",
        )

        modules = self.make_repo()
        (modules / ".gitmodules").write_text("forbidden\n", encoding="utf-8")
        git(modules, "add", ".gitmodules")
        git(modules, "commit", "-qm", "gitmodules")
        self.assertEqual(
            source.validate_fixture_source_v4(modules, self.expectation(source, modules)).blocked_reason,
            "SOURCE_GITMODULES_FORBIDDEN",
        )

    def test_v4_rejects_recomputed_arbitrary_upstream_content(self):
        source = __import__("scripts.rc0_candidate.source", fromlist=["unused"])
        repo = self.make_repo()
        target = repo / "upstream" / "opencode" / "packages" / "sdk" / "openapi.json"
        target.write_bytes(target.read_bytes() + b"\narbitrary self-consistent content\n")
        git(repo, "add", "upstream")
        git(repo, "commit", "-qm", "arbitrary upstream")
        result = source.validate_fixture_source_v4(repo, self.expectation(source, repo))
        self.assertEqual(result.blocked_reason, "SOURCE_UPSTREAM_POLICY_MISMATCH")

    def test_v4_rejects_wrong_tree_count_provenance_and_origin_aliases(self):
        source = __import__("scripts.rc0_candidate.source", fromlist=["unused"])
        repo = self.make_repo()
        expected = self.expectation(source, repo)
        wrong_tree = source.FixtureSourceExpectationV4(
            **{**expected.__dict__, "upstream_tree_oid": "1" * 40}
        )
        self.assertEqual(
            source.validate_fixture_source_v4(repo, wrong_tree).blocked_reason,
            "SOURCE_UPSTREAM_TREE_MISMATCH",
        )
        wrong_count = source.FixtureSourceExpectationV4(
            **{**expected.__dict__, "upstream_blob_count": expected.upstream_blob_count + 1}
        )
        self.assertEqual(
            source.validate_fixture_source_v4(repo, wrong_count).blocked_reason,
            "SOURCE_UPSTREAM_CONTENT_MISMATCH",
        )
        wrong_provenance = source.FixtureSourceExpectationV4(
            **{**expected.__dict__, "opencode_source_sha": "2" * 40}
        )
        self.assertEqual(
            source.validate_fixture_source_v4(repo, wrong_provenance).blocked_reason,
            "SOURCE_OPENCODE_PROVENANCE_MISMATCH",
        )
        for index, url in enumerate((
            "git@git.sourcecraft.dev:ryltsevmg/gocode.git",
            SOURCECRAFT + "?referrer=codex",
            "https://github.com/Ryltsevmg/gocode.git",
        )):
            with self.subTest(url=url):
                alias = self.make_repo()
                git(alias, "remote", "set-url", "origin", url)
                if index == 2:
                    git(alias, "config", "--add", "remote.origin.url", SOURCECRAFT)
                self.assertEqual(
                    source.validate_fixture_source_v4(alias, self.expectation(source, alias)).blocked_reason,
                    "SOURCE_REMOTE_IDENTITY_MISMATCH",
                )

    def test_v4_rejects_invalid_path_and_capture_race(self):
        source = __import__("scripts.rc0_candidate.source", fromlist=["unused"])
        encoded = self.make_repo()
        directory_fd = os.open(encoded / "upstream" / "opencode", os.O_RDONLY | os.O_DIRECTORY)
        try:
            descriptor = os.open(
                b"invalid-\xff", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(descriptor, b"bad path\n")
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_fd)
        git(encoded, "add", "upstream")
        git(encoded, "commit", "-qm", "invalid path")
        self.assertEqual(
            source.validate_fixture_source_v4(encoded, self.expectation(source, encoded)).blocked_reason,
            "SOURCE_UPSTREAM_POLICY_MISMATCH",
        )

        raced = self.make_repo()
        expected = self.expectation(source, raced)
        target = raced / "upstream" / "opencode" / "packages" / "sdk" / "openapi.json"

        def mutate(_stage, repository):
            target.write_bytes(target.read_bytes() + b"race\n")

        result = source.validate_fixture_source_v4(raced, expected, mutation_hook=mutate)
        self.assertEqual(result.blocked_reason, "SOURCE_SNAPSHOT_CHANGED")


class Rc0PolicyV4Tests(unittest.TestCase):
    def test_schema_registry_includes_closed_v4_successors(self):
        schemas = __import__("scripts.rc0_policy.schemas", fromlist=["unused"])
        v4 = {name for name in schemas.SCHEMA_FILES if name.endswith("/4")}
        self.assertEqual(len(v4), 11)
        for schema_id in v4:
            schema = schemas.load_schema(schema_id)
            self.assertEqual(schema["$id"], schema_id)
            self.assertEqual(schema["type"], "object")
            self.assertIs(schema["additionalProperties"], False)
