"""Closed successor coverage for the post-repair documentation overlay."""
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
V1_SCHEMA = "docs/schemas/pre-authority-document-delta-v1.schema.json"
MIXED = "1ea5dec17c36488819194b1d6aa443d932593966"


def git(repo, *args, index=None, stdin=None):
    env = None if index is None else {"GIT_INDEX_FILE": str(index)}
    return subprocess.run(("git", "-C", str(repo), *args), check=True, env=env, input=stdin, stdout=subprocess.PIPE).stdout


def module():
    value = types.ModuleType("pre_authority_overlay_v3")
    value.__file__ = str(DELTA)
    exec(DELTA.read_text(encoding="utf-8"), value.__dict__)
    exec(OVERLAY.read_text(encoding="utf-8"), value.__dict__)
    return value


class PreAuthorityDocumentOverlayV3Tests(unittest.TestCase):
    def repo(self):
        directory = tempfile.TemporaryDirectory(dir="/srv/data")
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name) / "repo"
        subprocess.run(("git", "clone", "-q", "--shared", str(ROOT), str(repo)), check=True)
        git(repo, "checkout", "-q", MIXED)
        return repo

    def candidate(self, value, repo):
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        git(repo, "update-index", "--force-remove", V1, index=index)
        for path in (*value.OVERLAY_V3_ADD_PATHS, *value.OVERLAY_V3_REPLACEMENTS,
                     value.OVERLAY_V3_SCHEMA_PATH, value.OVERLAY_V3_ARTIFACT_PATH):
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
            git(repo, "add", path, index=index)
        return index

    def persist(self, value, repo):
        index = self.candidate(value, repo)
        tree = git(repo, "write-tree", index=index).decode().strip()
        commit = git(repo, "commit-tree", tree, "-p", "HEAD", "-m", "overlay v3").decode().strip()
        git(repo, "update-ref", "HEAD", commit)
        git(repo, "read-tree", "HEAD")
        return index

    def test_repair_candidate_validates_and_persists_as_v3(self):
        value, repo = module(), self.repo()
        index = self.persist(value, repo)
        self.assertEqual(value.select_documentation_mode(repo, index_file=index), "overlay_v3")
        value.validate_pre_authority_document_overlay_v3(repo, index_file=index)
        value.validate_pre_authority_document_overlay_v3(repo)

    def test_v3_rejects_repair_add_mutation_deletion_and_downgrade(self):
        value, repo = module(), self.repo()
        index = self.candidate(value, repo)
        changed = git(repo, "hash-object", "-w", "--stdin", index=index, stdin=b"changed\n")
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{changed.decode().strip()},docs/00-foundation/DOCUMENTATION_RULES.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_BASE_MUTATION"):
            value.validate_pre_authority_document_overlay_v3(repo, index_file=index)
        index = self.candidate(value, repo)
        git(repo, "update-index", "--force-remove", "docs/00-foundation/DOCUMENTATION_RULES.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_BASE_MUTATION"):
            value.validate_pre_authority_document_overlay_v3(repo, index_file=index)
        index = self.candidate(value, repo)
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{changed.decode().strip()},{V1_SCHEMA}", index=index)
        with self.assertRaisesRegex(ValueError, "OVERLAY_V1_SCHEMA_PIN"):
            value.validate_pre_authority_document_overlay_v3(repo, index_file=index)
        index = self.candidate(value, repo)
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{changed.decode().strip()},docs/evil.md", index=index)
        with self.assertRaisesRegex(ValueError, "OVERLAY_V3_ADDITION_POLICY"):
            value.validate_pre_authority_document_overlay_v3(repo, index_file=index)
        index = self.candidate(value, repo)
        git(repo, "update-index", "--force-remove", value.OVERLAY_V3_ARTIFACT_PATH, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_DOWNGRADE"):
            value.select_documentation_mode(repo, index_file=index)

    def test_v3_rejects_document_drift_after_activation(self):
        value, repo = module(), self.repo()
        self.persist(value, repo)
        changed = git(repo, "hash-object", "-w", "--stdin", index=repo / "active.index", stdin=b"changed\n")
        for path, command, error in (
            ("docs/evil.md", ("--add", "--cacheinfo", f"100644,{changed.decode().strip()},docs/evil.md"), "OVERLAY_V3_ADDITION_POLICY"),
            ("docs/00-foundation/DOCUMENTATION_RULES.md", ("--add", "--cacheinfo", f"100644,{changed.decode().strip()},docs/00-foundation/DOCUMENTATION_RULES.md"), "DOCS_BASE_MUTATION"),
            ("docs/00-foundation/DOCUMENTATION_RULES.md", ("--force-remove", "docs/00-foundation/DOCUMENTATION_RULES.md"), "DOCS_BASE_MUTATION"),
            (V1_SCHEMA, ("--add", "--cacheinfo", f"100644,{changed.decode().strip()},{V1_SCHEMA}"), "OVERLAY_V1_SCHEMA_PIN"),
        ):
            with self.subTest(path=path, command=command):
                index = repo / "active.index"
                git(repo, "read-tree", "HEAD", index=index)
                git(repo, "update-index", *command, index=index)
                with self.assertRaisesRegex(ValueError, error):
                    value.validate_pre_authority_document_overlay_v3(repo, index_file=index)


if __name__ == "__main__":
    unittest.main()
