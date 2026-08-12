"""Two-phase reviewed-candidate admission regressions."""
import unittest

from scripts.tests.test_pre_authority_document_delta import admission, fixture_repo, git, load_module


class PreAuthorityAdmissionTests(unittest.TestCase):
    def test_allow_commit_requires_literal_true_without_ref_move(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        prepared = admission(module, repo, {})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        parent = git(repo, "rev-parse", "HEAD").decode().strip()
        for value in ("false", 1, object()):
            with self.subTest(value=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_COMMIT_REQUIRES_PHASE_C"):
                    module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=value)
                self.assertEqual(git(repo, "rev-parse", "HEAD").decode().strip(), parent)

    def test_manual_ref_admission_requires_literal_bool_without_ref_move(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        prepared = admission(module, repo, {})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        candidate = module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        parent = git(repo, "rev-parse", "HEAD").decode().strip()
        for value in ("false", 1, object()):
            with self.subTest(value=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_MANUAL_REF_INVALID"):
                    module.admit_pre_authority_candidate(repo, prepared, candidate, prepared["manifest_sha256"], manual_ref_admission=value)
                self.assertEqual(git(repo, "rev-parse", "HEAD").decode().strip(), parent)

    def test_manual_admission_uses_exact_reviewed_candidate_commit(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        prepared = admission(module, repo, {})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        candidate = module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        original, created = module.git_bytes, []
        def no_second_commit(repo_path, args, index_file=None, stdin=None):
            if args[:1] == ["commit-tree"]:
                created.append(args); raise AssertionError("second commit-tree")
            return original(repo_path, args, index_file, stdin)
        module.git_bytes = no_second_commit
        self.addCleanup(setattr, module, "git_bytes", original)
        commit = module.admit_pre_authority_candidate(repo, prepared, candidate, prepared["manifest_sha256"], manual_ref_admission=True)
        self.assertEqual((commit, created), (candidate["candidate_commit_oid"], []))

    def test_manual_admission_rejects_candidate_with_extra_parent(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        prepared = admission(module, repo, {})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        candidate = module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        base_tree = git(repo, "rev-parse", f"{candidate['parent_head_oid']}^{{tree}}").decode().strip()
        other = git(repo, "commit-tree", base_tree, "-p", candidate["parent_head_oid"], "-m", "other").decode().strip()
        candidate["candidate_commit_oid"] = git(repo, "commit-tree", candidate["candidate_tree_oid"], "-p", candidate["parent_head_oid"], "-p", other, "-m", "x").decode().strip()
        with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_TREE_CHANGED"):
            module.admit_pre_authority_candidate(repo, prepared, candidate, prepared["manifest_sha256"], manual_ref_admission=True)


if __name__ == "__main__":
    unittest.main()
