"""Temporary-repository regressions for the v2 pre-authority overlay."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[2]
DELTA = ROOT / "scripts/validate_docs_parts/pre_authority_document_delta.inc"
OVERLAY = ROOT / "scripts/validate_docs_parts/pre_authority_overlay_v2.inc"
V1 = "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json"
V2 = "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V2.json"
SCHEMA = "docs/schemas/pre-authority-document-overlay-v2.schema.json"
COMPOSED = "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json"
ANCHOR = "f6d0b2d6a5ccdda83ed80f9d0daefa785b622266"
MIXED_PREDECESSOR = "1ea5dec17c36488819194b1d6aa443d932593966"


def git(repo, *args, index=None):
    environment = None if index is None else {"GIT_INDEX_FILE": str(index)}
    return subprocess.run(("git", "-C", str(repo), *args), check=True, env=environment,
                          stdout=subprocess.PIPE).stdout


def module():
    value = types.ModuleType("pre_authority_overlay_v2")
    value.__file__ = str(DELTA)
    exec(DELTA.read_text(encoding="utf-8"), value.__dict__)
    exec(OVERLAY.read_text(encoding="utf-8"), value.__dict__)
    return value


class PreAuthorityDocumentOverlayV2Tests(unittest.TestCase):
    def clone(self, revision=ANCHOR):
        directory = tempfile.TemporaryDirectory(dir="/srv/data")
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name) / "repo"
        subprocess.run(("git", "clone", "-q", "--shared", str(ROOT), str(repo)), check=True)
        git(repo, "checkout", "-q", revision)
        return repo

    def candidate(self, repo):
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        for path in (SCHEMA, V2):
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        git(repo, "update-index", "--force-remove", V1, index=index)
        git(repo, "add", SCHEMA, V2, index=index)
        return index

    def repair_candidate(self, repo):
        index = repo / "repair.index"
        git(repo, "read-tree", "HEAD", index=index)
        git(repo, "update-index", "--force-remove", V1, index=index)
        return index

    def artifact(self, repo, index, mutate):
        value = json.loads((repo / V2).read_text())
        mutate(value)
        (repo / V2).write_text(json.dumps(value), encoding="utf-8")
        git(repo, "add", V2, index=index)

    def refresh(self, repo, index, artifact, path):
        mode, oid, _, found = git(repo, "ls-files", "--stage", "--", path, index=index).decode().split()
        record = next(record for record in artifact["records"] if record["path"] == found)
        record.update(candidate_mode=mode, candidate_blob_oid=oid,
                      candidate_sha256=__import__("hashlib").sha256((repo / path).read_bytes()).hexdigest())

    def test_v1_to_v2_overlay_is_exact_and_persistent(self):
        value, repo = module(), self.clone()
        index = self.candidate(repo)
        value.validate_pre_authority_document_overlay_v2(repo, index_file=index)
        tree = git(repo, "write-tree", index=index).decode().strip()
        commit = git(repo, "commit-tree", tree, "-p", "HEAD", "-m", "overlay").decode().strip()
        git(repo, "update-ref", "HEAD", commit)
        git(repo, "read-tree", "HEAD")
        value.validate_pre_authority_document_overlay_v2(repo)

    def test_exact_mixed_predecessor_requires_the_v3_successor(self):
        value, repo = module(), self.clone(MIXED_PREDECESSOR)
        index = self.repair_candidate(repo)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            value.select_documentation_mode(repo, index_file=index)
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{git(repo, 'rev-parse', f'HEAD:{V1}').decode().strip()},{V1}", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_CONFLICT"):
            value.select_documentation_mode(repo, index_file=index)

    def test_mixed_predecessor_repair_rejects_downgrade_composed_and_forgery(self):
        value, repo = module(), self.clone(MIXED_PREDECESSOR)
        index = self.repair_candidate(repo)
        git(repo, "update-index", "--force-remove", V2, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            value.select_documentation_mode(repo, index_file=index)
        index = self.repair_candidate(repo)
        git(repo, "update-index", "--force-remove", V2, index=index)
        (repo / COMPOSED).parent.mkdir(parents=True, exist_ok=True)
        (repo / COMPOSED).write_text("{}", encoding="utf-8")
        git(repo, "add", COMPOSED, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            value.select_documentation_mode(repo, index_file=index)
        repo = self.clone()
        index = repo / "forged-mixed.index"
        git(repo, "read-tree", "HEAD", index=index)
        (repo / V2).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / V2, repo / V2)
        git(repo, "add", V2, index=index)
        tree = git(repo, "write-tree", index=index).decode().strip()
        forged = git(repo, "commit-tree", tree, "-p", "HEAD", "-m", "forged mixed").decode().strip()
        git(repo, "update-ref", "HEAD", forged)
        git(repo, "read-tree", "HEAD")
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_CONFLICT"):
            value.select_documentation_mode(repo, index_file=self.repair_candidate(repo))
        repo = self.clone(MIXED_PREDECESSOR)
        index = self.repair_candidate(repo)
        (repo / V2).write_text("{}", encoding="utf-8")
        git(repo, "add", V2, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            value.validate_pre_authority_document_overlay_v2(repo, index_file=index)

    def test_overlay_rejects_state_and_record_mutations(self):
        value, repo = module(), self.clone()
        index = self.candidate(repo)
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{git(repo, 'rev-parse', f'HEAD:{V1}').decode().strip()},{V1}", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_CONFLICT"):
            value.select_documentation_mode(repo, index_file=index)
        index = self.candidate(repo)
        artifact = json.loads((repo / V2).read_text())
        artifact["records"] = artifact["records"][1:]
        (repo / V2).write_text(json.dumps(artifact), encoding="utf-8")
        git(repo, "add", V2, index=index)
        with self.assertRaisesRegex(ValueError, "OVERLAY_EXACTNESS"):
            value.validate_pre_authority_document_overlay_v2(repo, index_file=index)
        index = self.candidate(repo)
        tree = git(repo, "write-tree", index=index).decode().strip()
        commit = git(repo, "commit-tree", tree, "-p", "HEAD", "-m", "overlay").decode().strip()
        git(repo, "update-ref", "HEAD", commit)
        index = repo / "downgrade.index"
        git(repo, "read-tree", "HEAD", index=index)
        git(repo, "update-index", "--force-remove", V2, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            value.select_documentation_mode(repo, index_file=index)
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{git(repo, 'rev-parse', f'{ANCHOR}:{V1}').decode().strip()},{V1}", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            value.select_documentation_mode(repo, index_file=index)
        index = repo / "composed.index"
        git(repo, "read-tree", "HEAD", index=index)
        git(repo, "update-index", "--force-remove", V2, index=index)
        (repo / COMPOSED).parent.mkdir(parents=True, exist_ok=True)
        (repo / COMPOSED).write_text("{}", encoding="utf-8")
        git(repo, "add", COMPOSED, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            value.select_documentation_mode(repo, index_file=index)
        legacy = self.clone()
        git(legacy, "checkout", "-q", f"{ANCHOR}~2")
        index = self.candidate(legacy)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_TRANSITION"):
            value.select_documentation_mode(legacy, index_file=index)

    def test_overlay_rejects_closed_record_base_anchor_and_claim_mutations(self):
        value, repo = module(), self.clone()
        index = self.candidate(repo)
        self.artifact(repo, index, lambda artifact: artifact.update(records=artifact["records"][1:]))
        self.assertRaisesRegex(ValueError, "OVERLAY_EXACTNESS", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        self.artifact(repo, index, lambda artifact: artifact["records"].append({**artifact["records"][0], "path": "docs/extra.md"}))
        self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_OVERLAY_ARTIFACT", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        path = "docs/evil.md"
        (repo / path).write_text("ordinary\n", encoding="utf-8")
        git(repo, "add", path, index=index)
        artifact = json.loads((repo / V2).read_text())
        mode, oid, _, _ = git(repo, "ls-files", "--stage", "--", path, index=index).decode().split()
        artifact["records"].append({"operation": "add", "change_id": "TASK_1_BASELINE", "path": path, "candidate_mode": mode, "candidate_blob_oid": oid, "candidate_sha256": __import__("hashlib").sha256(b"ordinary\n").hexdigest(), "base_mode": None, "base_blob_oid": None, "base_sha256": None, "classification": "non_governed", "reason": "Outside the authoritative docs/ governance tree."})
        artifact["records"].sort(key=lambda record: record["path"])
        (repo / V2).write_text(json.dumps(artifact), encoding="utf-8")
        git(repo, "add", V2, index=index)
        self.assertRaisesRegex(ValueError, "OVERLAY_ADDITION_POLICY", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        self.artifact(repo, index, lambda artifact: artifact["records"][0].update(candidate_sha256="0" * 64))
        self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_OVERLAY_ARTIFACT", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        path = "docs/adr/ADR-0027-v1-platform-scope.md"
        (repo / path).write_text("changed\n", encoding="utf-8")
        git(repo, "add", path, index=index)
        artifact = json.loads((repo / V2).read_text())
        self.refresh(repo, index, artifact, path)
        (repo / V2).write_text(json.dumps(artifact), encoding="utf-8")
        git(repo, "add", V2, index=index)
        self.assertRaisesRegex(ValueError, "OVERLAY_BASELINE_PIN", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        target = "docs/adr/ADR-0027-v1-platform-scope.md"
        git(repo, "update-index", "--force-remove", target, index=index)
        self.artifact(repo, index, lambda artifact: artifact.update(records=[record for record in artifact["records"] if record["path"] != target]))
        self.assertRaisesRegex(ValueError, "DOCS_DELTA_DELETION", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        git(repo, "update-index", "--chmod=+x", target, index=index)
        self.assertRaisesRegex(ValueError, "DOCS_DELTA_(DELETION|ENTRY_INVALID)", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        changed = "docs/00-foundation/DOCUMENTATION_RULES.md"
        (repo / changed).write_text("changed\n", encoding="utf-8")
        git(repo, "add", changed, index=index)
        self.assertRaisesRegex(ValueError, "DOCS_BASE_MUTATION", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        (repo / SCHEMA).write_text("{}", encoding="utf-8")
        git(repo, "add", SCHEMA, index=index)
        self.assertRaisesRegex(ValueError, "PRE_AUTHORITY_OVERLAY_SCHEMA", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        snapshot = value.CandidateSnapshot.capture(repo, index_file=self.candidate(repo))
        value.OVERLAY_ANCHOR_TREE_BYTES_SHA256 = "0" * 64
        self.assertRaisesRegex(ValueError, "OVERLAY_ANCHOR_PIN", value._overlay_anchor, snapshot)

    def test_overlay_retains_v1_schema_and_ignores_replace_and_graft_lineage(self):
        value, repo = module(), self.clone()
        index = self.candidate(repo)
        git(repo, "update-index", "--force-remove", "docs/schemas/pre-authority-document-delta-v1.schema.json", index=index)
        self.assertRaisesRegex(ValueError, "OVERLAY_V1_SCHEMA_PIN", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        (repo / "docs/schemas/pre-authority-document-delta-v1.schema.json").write_text("{}", encoding="utf-8")
        git(repo, "add", "docs/schemas/pre-authority-document-delta-v1.schema.json", index=index)
        self.assertRaisesRegex(ValueError, "OVERLAY_V1_SCHEMA_PIN", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        index = self.candidate(repo)
        parent = git(repo, "rev-parse", f"{ANCHOR}^").decode().strip()
        forged = git(repo, "commit-tree", git(repo, "rev-parse", f"{ANCHOR}^{{tree}}").decode().strip(), "-p", parent, "-m", "forged").decode().strip()
        git(repo, "replace", ANCHOR, forged)
        graft = repo / git(repo, "rev-parse", "--git-path", "info/grafts").decode().strip()
        graft.parent.mkdir(parents=True, exist_ok=True)
        graft.write_text(f"{ANCHOR} {parent}\n", encoding="ascii")
        value.validate_pre_authority_document_overlay_v2(repo, index_file=index)

    def test_overlay_allows_readme_replace_and_scans_changed_claims(self):
        value, repo = module(), self.clone()
        index = self.candidate(repo)
        path = "docs/schemas/README.md"
        (repo / path).write_text("replacement\n", encoding="utf-8")
        git(repo, "add", path, index=index)
        artifact = json.loads((repo / V2).read_text())
        mode, oid, _, _ = git(repo, "ls-files", "--stage", "--", path, index=index).decode().split()
        base_mode, _, base_oid, _ = git(repo, "ls-tree", ANCHOR, "--", path).decode().split()
        artifact["records"].append({"operation": "replace", "change_id": "TASK_2", "path": path, "candidate_mode": mode, "candidate_blob_oid": oid, "candidate_sha256": __import__("hashlib").sha256(b"replacement\n").hexdigest(), "base_mode": base_mode, "base_blob_oid": base_oid, "base_sha256": __import__("hashlib").sha256(git(repo, "cat-file", "blob", f"{ANCHOR}:{path}")).hexdigest(), "classification": "governed", "reason": None})
        artifact["records"].sort(key=lambda record: record["path"])
        (repo / V2).write_text(json.dumps(artifact), encoding="utf-8")
        git(repo, "add", V2, index=index)
        value.validate_pre_authority_document_overlay_v2(repo, index_file=index)
        index = self.candidate(repo)
        path = "docs/schemas/README.md"
        (repo / path).write_text("approved\n", encoding="utf-8")
        git(repo, "add", path, index=index)
        artifact = json.loads((repo / V2).read_text())
        mode, oid, _, _ = git(repo, "ls-files", "--stage", "--", path, index=index).decode().split()
        base_mode, _, base_oid, _ = git(repo, "ls-tree", ANCHOR, "--", path).decode().split()
        artifact["records"].append({"operation": "replace", "change_id": "TASK_2", "path": path, "candidate_mode": mode, "candidate_blob_oid": oid, "candidate_sha256": __import__("hashlib").sha256(b"approved\n").hexdigest(), "base_mode": base_mode, "base_blob_oid": base_oid, "base_sha256": __import__("hashlib").sha256(git(repo, "cat-file", "blob", f"{ANCHOR}:{path}")).hexdigest(), "classification": "governed", "reason": None})
        artifact["records"].sort(key=lambda record: record["path"])
        (repo / V2).write_text(json.dumps(artifact), encoding="utf-8")
        git(repo, "add", V2, index=index)
        self.assertRaisesRegex(ValueError, "DOCS_AUTHORIZING_CLAIM", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)

    def test_overlay_requires_anchor_v1_and_v2_lineage(self):
        value, repo = module(), self.clone()
        git(repo, "checkout", "-q", f"{ANCHOR}^")
        index = self.candidate(repo)
        self.assertRaisesRegex(ValueError, "OVERLAY_ANCHOR_PIN", value.validate_pre_authority_document_overlay_v2, repo, index_file=index)
        legacy = self.clone()
        git(legacy, "checkout", "-q", f"{ANCHOR}~2")
        index = self.candidate(legacy)
        tree = git(legacy, "write-tree", index=index).decode().strip()
        forged = git(legacy, "commit-tree", tree, "-p", "HEAD", "-m", "forged").decode().strip()
        git(legacy, "update-ref", "HEAD", forged)
        git(legacy, "read-tree", "HEAD")
        self.assertRaisesRegex(ValueError, "OVERLAY_ANCHOR_PIN", value.validate_pre_authority_document_overlay_v2, legacy)


if __name__ == "__main__":
    unittest.main()
