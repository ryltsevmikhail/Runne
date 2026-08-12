"""Regression tests for the pre-authority documentation staging validator."""
import hashlib, json, os, types
from pathlib import Path
import subprocess, tempfile, unittest
ROOT = Path(__file__).resolve().parents[2]
TEST_TMP = Path("/srv/data")
MODULE = ROOT / "scripts" / "validate_docs_parts" / "pre_authority_document_delta.inc"
BASE_HASHES = {
    "document-universe-v1.json": "efeb9eabdfb03084a8cdc10c33acc4f8008dd73e1f750acb24513d19d1ab66b1",
    "governed-scope-v1.json": "18d80090ecc15ed0da8a935cbde1dfcc72308d96eb28cd0c0f9c0b6315daa5a4",
    "status-claims-v1.json": "d0dbbe23dbb553d090751a4f43537fd50ea46c298bdc9008f4ef80896067e77b",
}
def load_module():
    module = types.ModuleType("pre_authority_document_delta")
    module.__file__ = str(MODULE)
    exec(MODULE.read_text(encoding="utf-8"), module.__dict__)
    return module
def git(repo, *args, index=None, stdin=None):
    env = None if index is None else {"GIT_INDEX_FILE": str(index)}
    return subprocess.run(("git", "-C", str(repo), *args), input=stdin, check=True, env=env,
                          stdout=subprocess.PIPE).stdout
def write(repo, path, content):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content.read_bytes() if isinstance(content, Path) else content)
def fixture_repo():
    directory = tempfile.TemporaryDirectory(dir=TEST_TMP)
    repo = Path(directory.name)
    try:
        git(repo, "init", "-q", "-b", "main")
    except subprocess.CalledProcessError:
        git(repo, "init", "-q")
        git(repo, "symbolic-ref", "HEAD", "refs/heads/main")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "Test")
    for name in BASE_HASHES:
        write(repo, f"docs/rc0/{name}", (ROOT / "docs/rc0" / name).read_bytes())
    write(repo, "docs/00-foundation/DOCUMENTATION_RULES.md", b"base rules\n")
    git(repo, "add", "docs")
    git(repo, "commit", "-m", "legacy")
    return directory, repo
def reviewed(repo, changes):
    result = {}
    for path, content in changes.items():
        existing = subprocess.run(("git", "-C", str(repo), "cat-file", "-e", f"HEAD:{path}"), stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
        oid = git(repo, "hash-object", "--stdin", stdin=content).decode().strip()
        result[path] = {"operation": "modify" if existing else "add", "mode": "100644", "blob_oid": oid, "blob_sha256": hashlib.sha256(content).hexdigest()}
    return result
def admission(module, repo, changes):
    candidate = {path: (ROOT / path).read_bytes() for path in module.TASK1_LITERAL_ALLOWLIST}
    candidate.update(changes)
    artifact = json.loads(candidate[module.ARTIFACT_PATH])
    for record in artifact["documents"]:
        record["sha256"] = hashlib.sha256(candidate[record["path"]]).hexdigest()
    candidate[module.ARTIFACT_PATH] = json.dumps(artifact).encode()
    return module.prepare_pre_authority_admission(repo, candidate, reviewed(repo, candidate), repo.with_suffix(".review.json"))
def pre_authority_candidate(repo, index, documents):
    schema = ROOT / "docs/schemas/pre-authority-document-delta-v1.schema.json"
    write(repo, "docs/schemas/pre-authority-document-delta-v1.schema.json", schema)
    records = []
    for path in sorted(documents):
        state = "governed" if path in {"docs/adr/ADR-0027-v1-platform-scope.md", "docs/desktop/adr/ADR-0015-v1-platform-scope.md", "docs/superpowers/plans/2026-08-09-v1-platform-scope-local-contracts.md", "docs/superpowers/plans/2026-08-12-solo-project-owner-authority.md", "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md", "docs/superpowers/specs/2026-08-09-v1-platform-scope-qualification-design.md", "docs/superpowers/specs/2026-08-12-solo-project-owner-authority-design.md"} else "non_governed"
        records.append({"path": path, "classification": state,
                        "sha256": hashlib.sha256((repo / path).read_bytes()).hexdigest(),
                        "reason": None if state == "governed" else "Outside the authoritative docs/ governance tree."})
    value = {
        "schema_version": 1, "repository_id": "test", "mode": "pre_authority",
        "base_universe_bytes_sha256": BASE_HASHES["document-universe-v1.json"],
        "base_governed_scope_bytes_sha256": BASE_HASHES["governed-scope-v1.json"],
        "base_status_claims_bytes_sha256": BASE_HASHES["status-claims-v1.json"],
        "documents": records, "status_claims": [],
    }
    write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", json.dumps(value).encode())
    git(repo, "add", "docs/schemas/pre-authority-document-delta-v1.schema.json", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", *documents, index=index)
class PreAuthorityDocumentDeltaTests(unittest.TestCase):
    def test_selector_uses_real_index_not_ambient_or_checkout_artifact(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", b"{}")
        alternate = repo / "alternate.index"
        git(repo, "read-tree", "HEAD", index=alternate)
        original = os.environ.get("GIT_INDEX_FILE")
        self.addCleanup(lambda: os.environ.pop("GIT_INDEX_FILE", None) if original is None else os.environ.__setitem__("GIT_INDEX_FILE", original))
        os.environ["GIT_INDEX_FILE"] = str(alternate)
        self.assertEqual(module.select_documentation_mode(repo), "legacy")

    def test_legacy_selector_allows_unrelated_executable(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        write(repo, "scripts/executable.sh", b"#!/bin/sh\n")
        git(repo, "add", "scripts/executable.sh")
        git(repo, "update-index", "--chmod=+x", "scripts/executable.sh")
        self.assertEqual(module.select_documentation_mode(repo), "legacy")

    def test_pre_authority_artifact_requires_closed_fields_and_pinned_bases(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/schemas/pre-authority-document-delta-v1.schema.json", MODULE.parent.parent.parent / "docs/schemas/pre-authority-document-delta-v1.schema.json")
        artifact = {"schema_version": 1, "repository_id": "test", "mode": "pre_authority"}
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", json.dumps(artifact).encode())
        git(repo, "add", "docs/schemas/pre-authority-document-delta-v1.schema.json", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", index=index)
        with self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_ARTIFACT"):
            module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_predecessor_disallows_downgrade_and_conflicting_artifacts(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", b"{}")
        write(repo, "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json", b"{}")
        git(repo, "add", "docs/authority", "docs/rc0", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_CONFLICT"):
            module.select_documentation_mode(repo, index_file=index)

    def test_claim_projection_rejects_obfuscated_approval(self):
        module = load_module()
        self.assertTrue(module.protected_claim_diagnostics("app**rov**ed"))
        self.assertTrue(module.protected_claim_diagnostics("appro<!--x-->ved"))
        self.assertTrue(module.protected_claim_diagnostics("app\u200broved"))
    def test_rejects_delta_executable_and_confusable_claim(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/new.md", b"new\n")
        pre_authority_candidate(repo, index, ("docs/new.md",))
        git(repo, "update-index", "--chmod=+x", "docs/new.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_DELTA_ENTRY_INVALID"):
            module.validate_pre_authority_document_delta(repo, index_file=index)
        self.assertTrue(module.protected_claim_diagnostics("appгoved"))

    def test_unchanged_base_symlink_is_retained_but_mutation_fails(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        path = "upstream/desktop/paseo/AGENTS.md"
        oid = git(repo, "hash-object", "-w", "--stdin", stdin=b"CLAUDE.md").decode().strip()
        git(repo, "update-index", "--add", "--cacheinfo", f"120000,{oid},{path}")
        git(repo, "commit", "-m", "base symlink")
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/new.md", b"ordinary\n")
        pre_authority_candidate(repo, index, ("docs/new.md",))
        module.validate_pre_authority_document_delta(repo, index_file=index)
        changed = git(repo, "hash-object", "-w", "--stdin", stdin=b"OTHER.md").decode().strip()
        git(repo, "update-index", "--add", "--cacheinfo", f"120000,{changed},{path}", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_BASE_MUTATION"):
            module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_temporary_admission_cas_rejects_moved_head(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        prepared = admission(module, repo, {"scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md": b"new\n"})
        self.addCleanup(prepared["temporary_directory"].cleanup)
        manifest = module.strict_json(prepared["manifest_path"].read_bytes(), "bad")
        self.assertEqual(manifest["paths"]["scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md"]["mode"], "100644")
        git(repo, "commit", "--allow-empty", "-m", "move")
        with self.assertRaisesRegex(ValueError, "DOCS_HEAD_CHANGED"):
            module.commit_pre_authority_admission(repo, prepared, "test", prepared["manifest_sha256"], allow_commit=True)

    def test_delta_requires_exact_records_and_closed_non_governed_reason(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "notes.md", b"ordinary note\n")
        pre_authority_candidate(repo, index, ("notes.md",))
        artifact_path = repo / "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json"
        artifact = json.loads(artifact_path.read_text())
        artifact["documents"][0]["reason"] = "wrong"
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", json.dumps(artifact).encode())
        git(repo, "add", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", index=index)
        with self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_ARTIFACT"):
            module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_cumulative_delta_membership_survives_head_advance(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        write(repo, "docs/new.md", b"ordinary\n")
        pre_authority_candidate(repo, None, ("docs/new.md",))
        module.validate_pre_authority_document_delta(repo)
        git(repo, "commit", "-m", "pre-authority")
        snapshot = module.CandidateSnapshot.capture(repo)
        self.assertEqual(module._document_paths(snapshot, module._base_paths(snapshot)), {"docs/new.md"})
        module.validate_pre_authority_document_delta(repo)
        def candidate(name):
            index = repo / f"{name}.index"
            git(repo, "read-tree", "HEAD", index=index)
            write(repo, module.ARTIFACT_PATH, git(repo, "show", f"HEAD:{module.ARTIFACT_PATH}"))
            return index
        index = candidate("missing")
        write(repo, "docs/missing.md", b"missing\n")
        git(repo, "add", "docs/missing.md", index=index)
        self.assertRaisesRegex(ValueError, "DOCS_DELTA_EXACTNESS", module.validate_pre_authority_document_delta, repo, index_file=index)
        index = candidate("extra")
        artifact = json.loads((repo / module.ARTIFACT_PATH).read_text())
        artifact["documents"].append({**artifact["documents"][0], "path": "docs/extra.md"})
        write(repo, module.ARTIFACT_PATH, json.dumps(artifact).encode())
        git(repo, "add", module.ARTIFACT_PATH, index=index)
        self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_ARTIFACT", module.validate_pre_authority_document_delta, repo, index_file=index)
        index = candidate("stale")
        write(repo, "docs/new.md", b"stale\n")
        git(repo, "add", "docs/new.md", index=index)
        self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_ARTIFACT", module.validate_pre_authority_document_delta, repo, index_file=index)
        index = candidate("updated")
        artifact = json.loads((repo / module.ARTIFACT_PATH).read_text())
        write(repo, "docs/new.md", b"updated\n")
        artifact["documents"][0]["sha256"] = hashlib.sha256(b"updated\n").hexdigest()
        write(repo, module.ARTIFACT_PATH, json.dumps(artifact).encode())
        git(repo, "add", "docs/new.md", module.ARTIFACT_PATH, index=index)
        module.validate_pre_authority_document_delta(repo, index_file=index)
        index = candidate("delete")
        git(repo, "update-index", "--force-remove", "docs/new.md", index=index)
        artifact = json.loads((repo / module.ARTIFACT_PATH).read_text())
        artifact["documents"] = []
        write(repo, module.ARTIFACT_PATH, json.dumps(artifact).encode())
        git(repo, "add", module.ARTIFACT_PATH, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_DELTA_(DELETION|EXACTNESS)"):
            module.validate_pre_authority_document_delta(repo, index_file=index)
        index = candidate("rename")
        git(repo, "update-index", "--force-remove", "docs/new.md", index=index)
        write(repo, "docs/renamed.md", b"ordinary\n")
        artifact = json.loads((repo / module.ARTIFACT_PATH).read_text())
        artifact["documents"][0]["path"] = "docs/renamed.md"
        write(repo, module.ARTIFACT_PATH, json.dumps(artifact).encode())
        git(repo, "add", module.ARTIFACT_PATH, "docs/renamed.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_DELTA_(DELETION|EXACTNESS)"):
            module.validate_pre_authority_document_delta(repo, index_file=index)
        index = candidate("mode")
        git(repo, "update-index", "--chmod=+x", "docs/new.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_DELTA_ENTRY_INVALID"):
            module.validate_pre_authority_document_delta(repo, index_file=index)

    def test_snapshot_json_path_and_claim_closure_are_fail_closed(self):
        module = load_module()
        self.assertRaisesRegex(ValueError, "DUP", module.strict_json, b'{"x":{"y":1,"y":2}}', "DUP")
        for path in (b"docs/../x.md", b"docs/a\\b.md", b"docs/a:b.md", "docs/a\u200eb.md".encode()):
            with self.assertRaisesRegex(ValueError, "DOCS_PATH_INVALID"):
                module.safe_path(path)
        for claim in ("app**rov**ed", "appro<!--x-->ved", "app\u200broved", "appгoved", "active activation", "PASS"):
            self.assertTrue(module.protected_claim_diagnostics(claim), claim)

    def test_schema_pin_and_composed_transition_fail_closed(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/schemas/pre-authority-document-delta-v1.schema.json", b"{}")
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", b"{}")
        git(repo, "add", "docs/schemas/pre-authority-document-delta-v1.schema.json", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", index=index)
        with self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_SCHEMA_PIN"):
            module.validate_pre_authority_document_delta(repo, index_file=index)
        git(repo, "read-tree", "HEAD", index=index)
        write(repo, "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json", b"{}")
        git(repo, "add", "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_COMPOSED_VALIDATOR_UNAVAILABLE"):
            module.select_documentation_mode(repo, index_file=index)

    def test_predecessor_downgrade_matrix_uses_captured_head(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        write(repo, "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", b"{}")
        git(repo, "add", "docs/authority")
        git(repo, "commit", "-m", "predecessor")
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        git(repo, "update-index", "--force-remove", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            module.select_documentation_mode(repo, index_file=index)

    def test_admission_manifest_records_exact_add_and_modify(self):
        module = load_module()
        temp, repo = fixture_repo()
        self.addCleanup(temp.cleanup)
        changes = {"scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md": b"new\n"}
        prepared = admission(module, repo, changes)
        self.addCleanup(prepared["temporary_directory"].cleanup)
        paths = module.strict_json(prepared["manifest_path"].read_bytes(), "bad")["paths"]
        self.assertEqual(paths["scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md"]["operation"], "add")
        self.assertEqual(paths["docs/00-foundation/DOCUMENTATION_RULES.md"]["operation"], "modify")
        with self.assertRaisesRegex(ValueError, "DOCS_ADMISSION_COMMIT_REQUIRES_PHASE_C"):
            module.commit_pre_authority_admission(repo, prepared, "no", prepared["manifest_sha256"])
if __name__ == "__main__":
    unittest.main()
