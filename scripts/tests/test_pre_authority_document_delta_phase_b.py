"""Phase B public-interface regression cases for pre-authority validation."""
import json
from pathlib import Path
import unittest

from scripts.tests.test_pre_authority_document_delta import admission, fixture_repo, git, load_module, pre_authority_candidate, reviewed, write


README = "scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md"
TASK1_PATHS = {
    "docs/00-foundation/DOCUMENTATION_RULES.md",
    "docs/schemas/pre-authority-document-delta-v1.schema.json",
    "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json",
    "docs/adr/ADR-0027-v1-platform-scope.md",
    "docs/desktop/adr/ADR-0015-v1-platform-scope.md",
    "docs/superpowers/plans/2026-08-09-v1-platform-scope-local-contracts.md",
    "docs/superpowers/plans/2026-08-12-solo-project-owner-authority.md",
    "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
    "docs/superpowers/specs/2026-08-09-v1-platform-scope-qualification-design.md",
    "docs/superpowers/specs/2026-08-12-solo-project-owner-authority-design.md",
    README, "scripts/validate_docs_impl.inc", "scripts/validate_docs_parts/documentation_rules.inc",
    "scripts/validate_docs_parts/pre_authority_admission.inc", "scripts/validate_docs_parts/pre_authority_claims.inc",
    "scripts/validate_docs_parts/pre_authority_document_delta.inc", "scripts/validate_docs_parts/pre_authority_legacy.inc",
    "scripts/validate_docs_parts/pre_authority_snapshot.inc", "scripts/tests/test_pre_authority_document_delta.py",
    "scripts/tests/test_pre_authority_document_delta_matrix.py", "scripts/tests/test_pre_authority_document_delta_phase_b.py", "scripts/tests/test_pre_authority_document_delta_admission.py",
}


class PreAuthorityPhaseBTests(unittest.TestCase):
    def repo(self):
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        return repo

    def test_claim_grants_entities_variation_and_benign_multilingual_text(self):
        module = load_module()
        for text in ("authority: granted", "authority-granted", "authority is granted", "auth&#111;rity: granted", "appro\ufe0fved"):
            self.assertTrue(module.protected_claim_diagnostics(text), text)
        self.assertFalse(module.protected_claim_diagnostics("Русский текст и English prose без claim."))

    def test_literal_allowlist_and_external_review_manifest_are_required(self):
        module, repo = load_module(), self.repo()
        changes = {README: b"inert\n"}
        with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_ALLOWLIST_INVALID"):
            module.prepare_pre_authority_admission(repo, {"docs/new.md": b"new\n"}, reviewed(repo, {"docs/new.md": b"new\n"}), repo.with_suffix(".review"))
        with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_ALLOWLIST_INVALID"):
            module.prepare_pre_authority_admission(repo, changes, reviewed(repo, changes), repo / "review.json")

    def test_prepare_rejects_an_incomplete_literal_transaction(self):
        module, repo = load_module(), self.repo()
        changes = {README: b"inert\n"}
        with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_ALLOWLIST_INVALID"):
            module.prepare_pre_authority_admission(repo, changes, reviewed(repo, changes), repo.with_suffix(".review"))

    def test_manifest_ref_and_index_mutations_fail_before_temp_commit(self):
        module, repo = load_module(), self.repo()
        changes = {README: b"inert\n"}
        prepared = admission(module, repo, changes)
        self.addCleanup(prepared["temporary_directory"].cleanup)
        prepared["manifest_path"].write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_MANIFEST_CHANGED"):
            module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        prepared = admission(module, repo, changes)
        self.addCleanup(prepared["temporary_directory"].cleanup)
        git(repo, "branch", "other", "HEAD")
        git(repo, "symbolic-ref", "HEAD", "refs/heads/other")
        with self.assertRaisesRegex(ValueError, "DOCS_HEAD_CHANGED"):
            module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)

    def test_manifest_mode_and_immutable_mutations_fail_public_interfaces(self):
        module, repo = load_module(), self.repo()
        changes = {README: b"inert\n"}
        prepared = admission(module, repo, changes)
        self.addCleanup(prepared["temporary_directory"].cleanup)
        manifest = module.strict_json(prepared["manifest_path"].read_bytes(), "bad")
        git(repo, "update-index", "--add", "--cacheinfo", f"100755,{manifest['paths'][README]['blob_oid']},{README}", index=prepared["index_file"])
        with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_DIFF_INVALID"):
            module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        for path in module.BASE_DIGESTS:
            index = repo / f"{Path(path).name}.index"
            git(repo, "read-tree", "HEAD", index=index)
            oid = git(repo, "hash-object", "-w", "--stdin", stdin=b"mutated").decode().strip()
            git(repo, "update-index", "--add", "--cacheinfo", f"100644,{oid},{path}", index=index)
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "DOCS_IMMUTABLE_MANIFEST_MUTATION"):
                    module.validate_immutable_rc0_manifests(repo, index_file=index)

    def test_base_and_control_entry_mutations_fail_pre_authority_interface(self):
        module, repo = load_module(), self.repo()
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/new.markdown", b"ordinary\n")
        pre_authority_candidate(repo, index, ("docs/new.markdown",))
        git(repo, "update-index", "--force-remove", "docs/00-foundation/DOCUMENTATION_RULES.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_BASE_MUTATION"):
            module.validate_pre_authority_document_delta(repo, index_file=index)
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/new.md", b"ordinary\n")
        pre_authority_candidate(repo, index, ("docs/new.md",))
        for control in (module.SCHEMA_PATH, module.ARTIFACT_PATH):
            git(repo, "update-index", "--chmod=+x", control, index=index)
            with self.subTest(control=control):
                with self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_SCHEMA_PIN"):
                    module.validate_pre_authority_document_delta(repo, index_file=index)
            git(repo, "update-index", "--chmod=-x", control, index=index)

    def test_only_pinned_documentation_rules_base_override_is_allowed(self):
        module, repo = load_module(), self.repo()
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/new.md", b"ordinary\n")
        pre_authority_candidate(repo, index, ("docs/new.md",))
        write(repo, "docs/00-foundation/DOCUMENTATION_RULES.md", (Path(module.__file__).parents[2] / "docs/00-foundation/DOCUMENTATION_RULES.md").read_bytes())
        git(repo, "add", "docs/00-foundation/DOCUMENTATION_RULES.md", index=index)
        module.validate_pre_authority_document_delta(repo, index_file=index)
        write(repo, "docs/00-foundation/DOCUMENTATION_RULES.md", b"unreviewed base mutation\n")
        git(repo, "add", "docs/00-foundation/DOCUMENTATION_RULES.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_BASE_MUTATION"):
            module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_valid_pre_candidate_is_validated_during_admission(self):
        module, repo = load_module(), self.repo()
        content = b"inert\n"
        prepared = admission(module, repo, {README: content})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        self.assertTrue(prepared["manifest_path"].is_file())

    def test_current_artifact_documents_are_non_authorizing_but_direct_claims_fail(self):
        module = load_module()
        root = Path(module.__file__).parents[2]
        artifact = json.loads((root / module.ARTIFACT_PATH).read_text(encoding="utf-8"))
        for record in artifact["documents"]:
            with self.subTest(path=record["path"]):
                self.assertFalse(module.protected_claim_diagnostics((root / record["path"]).read_bytes()))
        for text in ("approved", "status: app**rov**ed", "This change is approved.", "authority is gr&#97;nted", "status: appr\u043eved", "status: apprοved", "This is authοrized.", "status: approνed", "status: approve\u0501", "authority is grante\u0501", "decision: verif\u0501ed", "disposition: satisfie\u03c2", "This change is approve\u0501.", "approve\u0501"):
            with self.subTest(text=text):
                self.assertTrue(module.protected_claim_diagnostics(text))
        for text in ("The proposal is not approved.", "This text does not authorize any action."):
            with self.subTest(text=text):
                self.assertFalse(module.protected_claim_diagnostics(text))

    def test_full_literal_candidate_is_validated_before_admission(self):
        module, repo = load_module(), self.repo()
        root = Path(module.__file__).parents[2]
        self.assertEqual(module.TASK1_LITERAL_ALLOWLIST, TASK1_PATHS)
        changes = {path: (root / path).read_bytes() for path in TASK1_PATHS}
        prepared = module.prepare_pre_authority_admission(repo, changes, reviewed(repo, changes), repo.with_suffix(".review"))
        self.addCleanup(prepared["temporary_directory"].cleanup)
        manifest = module.strict_json(prepared["manifest_path"].read_bytes(), "bad")
        self.assertEqual(set(manifest["paths"]), TASK1_PATHS)

    def test_admission_rejects_old_mode_transition_to_regular_file(self):
        module, repo = load_module(), self.repo()
        git(repo, "update-index", "--chmod=+x", "docs/00-foundation/DOCUMENTATION_RULES.md")
        git(repo, "commit", "-m", "executable base")
        with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_DIFF_INVALID"):
            admission(module, repo, {})

    def test_prepare_rejects_same_oid_head_switch_during_validation(self):
        module, repo = load_module(), self.repo()
        git(repo, "branch", "other", "HEAD")
        original = module._validate_pre
        def switch(snapshot):
            original(snapshot)
            git(repo, "symbolic-ref", "HEAD", "refs/heads/other")
        module._validate_pre = switch
        self.addCleanup(setattr, module, "_validate_pre", original)
        with self.assertRaisesRegex(ValueError, "DOCS_HEAD_CHANGED"):
            admission(module, repo, {})

    def test_commit_rejects_same_oid_head_switch_at_final_cas(self):
        module, repo = load_module(), self.repo()
        prepared = admission(module, repo, {})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        candidate = module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        git(repo, "branch", "other", "HEAD")
        git(repo, "symbolic-ref", "HEAD", "refs/heads/other")
        with self.assertRaisesRegex(ValueError, "DOCS_HEAD_CHANGED"):
            module.admit_pre_authority_candidate(repo, prepared, candidate, prepared["manifest_sha256"], manual_ref_admission=True)

    def test_post_cas_head_switch_preserves_current_refs_without_rollback(self):
        module, repo = load_module(), self.repo()
        prepared = admission(module, repo, {})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        candidate = module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        parent = git(repo, "rev-parse", "HEAD").decode().strip()
        git(repo, "branch", "other", "HEAD")
        original = module.git_bytes
        def switch(repo_path, args, index_file=None, stdin=None):
            value = original(repo_path, args, index_file, stdin)
            if args[:2] == ["update-ref", "refs/heads/main"] and args[2] != parent:
                git(repo, "symbolic-ref", "HEAD", "refs/heads/other")
            return value
        module.git_bytes = switch
        self.addCleanup(setattr, module, "git_bytes", original)
        with self.assertRaisesRegex(ValueError, "DOCS_HEAD_CHANGED"):
            module.admit_pre_authority_candidate(repo, prepared, candidate, prepared["manifest_sha256"], manual_ref_admission=True)
        self.assertNotEqual(git(repo, "rev-parse", "refs/heads/main").decode().strip(), parent)
        self.assertEqual(git(repo, "rev-parse", "refs/heads/other").decode().strip(), parent)

    def test_unconfirmed_manual_admission_returns_candidate_without_ref_move(self):
        module, repo = load_module(), self.repo()
        prepared = admission(module, repo, {})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        parent = git(repo, "rev-parse", "HEAD").decode().strip()
        result = module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        self.assertEqual(result["status"], "BLOCKED_AT_MANUAL_REF_ADMISSION")
        self.assertEqual(result["parent_head_oid"], parent)
        self.assertEqual(git(repo, "rev-parse", "HEAD").decode().strip(), parent)
        self.assertEqual(git(repo, "rev-parse", f"{result['candidate_commit_oid']}^{{tree}}").decode().strip(), result["candidate_tree_oid"])

    def test_concurrent_branch_move_is_never_rolled_back(self):
        module, repo = load_module(), self.repo()
        prepared = admission(module, repo, {})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        candidate = module.commit_pre_authority_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        original = module._cas_ref
        moved = []
        def concurrent(*args):
            git(repo, "commit", "--allow-empty", "-m", "concurrent")
            moved.append(git(repo, "rev-parse", "HEAD").decode().strip())
            return original(*args)
        module._cas_ref = concurrent
        self.addCleanup(setattr, module, "_cas_ref", original)
        with self.assertRaisesRegex(ValueError, "DOCS_HEAD_CHANGED"):
            module.admit_pre_authority_candidate(repo, prepared, candidate, prepared["manifest_sha256"], manual_ref_admission=True)
        self.assertEqual(git(repo, "rev-parse", "refs/heads/main").decode().strip(), moved[0])

    def test_status_claims_reconcile_bidirectionally_with_front_matter(self):
        module, repo = load_module(), self.repo()
        index, path = repo / "claims.index", "docs/adr/ADR-0027-v1-platform-scope.md"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, path, b'---\nblocked_status: "BLOCKED"\nevidence_binding: "gocode.rc0.evidence-profile/3"\n---\ninert\n')
        pre_authority_candidate(repo, index, (path,))
        artifact_path = repo / module.ARTIFACT_PATH
        artifact = json.loads(artifact_path.read_text())
        claim = {"path": path, "claim_kind": "blocked_status", "disposition": "BLOCKED", "evidence_binding": module.EVIDENCE_PROFILE}
        for records, code in (([], "DOCS_STATUS_CLAIM_RECONCILIATION"), ([{**claim, "disposition": "OUT_OF_SCOPE"}], "PRE_AUTHORITY_ARTIFACT"), ([claim, claim], "PRE_AUTHORITY_ARTIFACT")):
            with self.subTest(records=records):
                artifact["status_claims"] = records
                write(repo, module.ARTIFACT_PATH, json.dumps(artifact).encode())
                git(repo, "add", module.ARTIFACT_PATH, index=index)
                with self.assertRaisesRegex(ValueError, code):
                    module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_multistage_index_and_ambient_divergence_fail_public_interfaces(self):
        module, repo = load_module(), self.repo()
        index = repo / "multi.index"
        git(repo, "read-tree", "HEAD", index=index)
        oid = git(repo, "rev-parse", "HEAD:docs/rc0/document-universe-v1.json").decode().strip()
        git(repo, "update-index", "-z", "--index-info", index=index, stdin=f"100644 {oid} 1\tdocs/rc0/document-universe-v1.json\0".encode())
        with self.assertRaisesRegex(ValueError, "DOCS_INDEX_RECORD_INVALID"):
            module.select_documentation_mode(repo, index_file=index)
        alternate = repo / "alternate.index"
        git(repo, "read-tree", "HEAD", index=alternate)
        write(repo, module.ARTIFACT_PATH, b"{}")
        git(repo, "add", module.ARTIFACT_PATH, index=alternate)
        self.assertEqual(module.select_documentation_mode(repo), "legacy")

    def test_legacy_snapshot_resolves_two_safe_symlinks_and_rejects_hostile_targets(self):
        module = load_module()
        entry = module.IndexEntry
        entries = {
            "upstream/desktop/paseo/AGENTS.md": entry("0", "120000", "a", b"CLAUDE.md"),
            "upstream/desktop/paseo/CLAUDE.md": entry("0", "100644", "b", b"safe\n"),
            "upstream/desktop/paseo/packages/server/AGENTS.md": entry("0", "120000", "c", b"CLAUDE.md"),
            "upstream/desktop/paseo/packages/server/CLAUDE.md": entry("0", "100644", "d", b"safe nested\n"),
        }
        snapshot = module.CandidateSnapshot(Path("."), "head", entries)
        module.validate_document_universe = lambda root, **_: [(root / path).read_bytes() for path in entries if path.endswith("AGENTS.md")]
        self.assertEqual(module.validate_legacy_snapshot(snapshot), [b"safe\n", b"safe nested\n"])
        for target in (b"/absolute.md", b"../../escape.md", b"missing.md"):
            with self.subTest(target=target):
                hostile = {"docs/AGENTS.md": entry("0", "120000", "x", target)}
                with self.assertRaisesRegex(ValueError, "DOCS_LEGACY_SYMLINK_INVALID"):
                    module.snapshot_symlink_target(hostile, "docs/AGENTS.md")
        cycle = {"docs/A.md": entry("0", "120000", "x", b"B.md"), "docs/B.md": entry("0", "120000", "y", b"A.md")}
        with self.assertRaisesRegex(ValueError, "DOCS_LEGACY_SYMLINK_INVALID"):
            module.snapshot_symlink_target(cycle, "docs/A.md")



if __name__ == "__main__":
    unittest.main()
