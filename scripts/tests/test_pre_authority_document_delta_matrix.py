"""Exhaustive temporary-repository negative matrix for pre-authority staging."""
from pathlib import Path
import unittest

from scripts.tests.test_pre_authority_document_delta import (
    BASE_HASHES, ROOT, admission, fixture_repo, git, load_module, pre_authority_candidate, write,
)


class PreAuthorityDocumentDeltaMatrixTests(unittest.TestCase):
    def candidate(self, files):
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        for path, content in files.items():
            write(repo, path, content)
        pre_authority_candidate(repo, index, tuple(files))
        return repo, index

    def test_frozen_snapshot_survives_index_and_checkout_replacement(self):
        module = load_module()
        repo, index = self.candidate({"docs/new.md": b"ordinary\n"})
        snapshot = module.CandidateSnapshot.capture(repo, index_file=index)
        self.assertEqual(module._select(snapshot), "pre_authority")
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", b"{}")
        write(repo, "docs/schemas/pre-authority-document-delta-v1.schema.json", b"{}")
        git(repo, "add", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", index=index)
        self.assertEqual(module._select(snapshot), "pre_authority")
        module._validate_pre(snapshot)
        with self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_ARTIFACT"):
            module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_schema_pin_rejects_weakened_schema_with_matching_artifact(self):
        module = load_module()
        repo, index = self.candidate({"docs/new.md": b"ordinary\n"})
        write(repo, "docs/schemas/pre-authority-document-delta-v1.schema.json", b'{"type":"object"}')
        git(repo, "add", "docs/schemas/pre-authority-document-delta-v1.schema.json", index=index)
        with self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_SCHEMA_PIN"):
            module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_predecessor_matrix_and_worktree_markers(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", b"{}")
        self.assertEqual(module.select_documentation_mode(repo, index_file=index), "legacy")
        git(repo, "add", "docs/authority")
        git(repo, "commit", "-m", "predecessor pre")
        git(repo, "read-tree", "HEAD", index=index)
        git(repo, "update-index", "--force-remove", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            module.select_documentation_mode(repo, index_file=index)
        git(repo, "rm", "--cached", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json")
        write(repo, "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json", b"{}")
        git(repo, "add", "docs/rc0")
        git(repo, "commit", "-m", "predecessor composed")
        git(repo, "read-tree", "HEAD", index=index)
        git(repo, "update-index", "--force-remove", "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json", index=index)
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", b"{}")
        git(repo, "add", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            module.select_documentation_mode(repo, index_file=index)

    def test_claim_matrix_scans_front_matter_governed_and_non_governed(self):
        module = load_module()
        cases = (
            ("docs/governed.md", b"---\ntitle: x\n---\napp**rov**ed"),
            ("docs/governed.md", b"---\ntitle: x\n---\nappro<!--x-->ved"),
            ("docs/governed.md", "---\ntitle: x\n---\napp\u200broved".encode()),
            ("docs/governed.md", "---\ntitle: x\n---\nappгoved".encode()),
            ("docs/governed.md", "---\ntitle: x\n---\nauthоrized".encode()),
            ("docs/governed.md", "---\ntitle: x\n---\nappr\u202eoved".encode()),
            ("scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md", b"appro<!--x-->ved"),
        )
        for path, content in cases:
            with self.subTest(path=path, content=content):
                repo, index = self.candidate({path: content})
                with self.assertRaisesRegex(ValueError, "DOCS_AUTHORIZING_CLAIM"):
                    module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_json_and_index_path_matrix_fails_closed(self):
        module = load_module()
        self.assertRaisesRegex(ValueError, "DUP", module.strict_json, b'{"a":{"b":1,"b":2}}', "DUP")
        for path in (b"C:/drive.md", b"docs/a\x01.md", "docs/a\u202eb.md".encode()):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "DOCS_PATH_INVALID"):
                    module.safe_path(path)
        self.assertRaisesRegex(ValueError, "DOCS_PATH_INVALID", module.safe_path, "docs/cafe\u0301.md".encode())

    def test_casefold_and_nonregular_delta_entries_are_rejected(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/A.md", b"a")
        write(repo, "docs/a.md", b"b")
        git(repo, "add", "docs/A.md", "docs/a.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_INDEX_RECORD_INVALID"):
            module.select_documentation_mode(repo, index_file=index)
        for kind in ("executable", "symlink", "gitlink"):
            repo, index = self.candidate({"docs/new.md": b"ordinary\n"})
            if kind == "executable":
                git(repo, "update-index", "--chmod=+x", "docs/new.md", index=index)
            elif kind == "symlink":
                target = repo / "docs/new.md"
                target.unlink()
                target.symlink_to("target.md")
                git(repo, "add", "docs/new.md", index=index)
            else:
                oid = git(repo, "rev-parse", "HEAD").decode().strip()
                git(repo, "update-index", "--add", "--cacheinfo", f"160000,{oid},docs/new.md", index=index)
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, "DOCS_DELTA_ENTRY_INVALID"):
                    module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_admission_rejects_extra_delete_and_reviewed_content_change(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        write(repo, "docs/ordinary.md", b"base\n")
        git(repo, "add", "docs/ordinary.md")
        git(repo, "commit", "-m", "ordinary")
        for mutation in ("delete", "content", "rename"):
            with self.subTest(mutation=mutation):
                changes = {"scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md": b"new\n"}
                prepared = admission(module, repo, changes)
                self.addCleanup(prepared["temporary_directory"].cleanup)
                if mutation == "delete":
                    git(repo, "update-index", "--force-remove", "docs/ordinary.md", index=prepared["index_file"])
                else:
                    manifest = module.strict_json(prepared["manifest_path"].read_bytes(), "bad")
                    oid = manifest["paths"]["scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md"]["blob_oid"] if mutation == "rename" else module.git_bytes(repo, ["hash-object", "-w", "--stdin"], stdin=b"changed\n").decode().strip()
                    path = "scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/RENAMED.md" if mutation == "rename" else "scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md"
                    if mutation == "rename":
                        git(repo, "update-index", "--force-remove", "scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md", index=prepared["index_file"])
                    git(repo, "update-index", "--add", "--cacheinfo", f"100644,{oid},{path}", index=prepared["index_file"])
                with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_DIFF_INVALID"):
                    module.commit_pre_authority_admission(repo, prepared, "no", prepared["manifest_sha256"], allow_commit=True)

    def test_admission_commit_tree_equals_validated_tree_in_temporary_repo(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        prepared = admission(module, repo, {"scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md": b"new\n"})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        candidate = module.commit_pre_authority_admission(repo, prepared, "temporary", prepared["manifest_sha256"], allow_commit=True)
        commit = module.admit_pre_authority_candidate(repo, prepared, candidate, prepared["manifest_sha256"], manual_ref_admission=True)
        manifest = module.strict_json(prepared["manifest_path"].read_bytes(), "bad")
        self.assertEqual(git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip(), manifest["candidate_tree_oid"])

    def test_admission_uses_literal_allowlist_including_fixture_readme(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        readme = "scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md"
        prepared = admission(module, repo, {"scripts/tests/test_pre_authority_document_delta_matrix.py": b"new\n", readme: b"inert\n"})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        manifest = module.strict_json(prepared["manifest_path"].read_bytes(), "bad")
        self.assertEqual(set(manifest["paths"]), module.TASK1_LITERAL_ALLOWLIST)

    def test_legacy_dispatcher_keeps_universe_validation(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        module.validate_document_universe = lambda root, **_: ["LEGACY_FULL_VALIDATION"]
        self.assertEqual(module.validate_documentation_mode(repo), ["LEGACY_FULL_VALIDATION"])

if __name__ == "__main__":
    unittest.main()
