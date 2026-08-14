"""Closed upgrade coverage for the desktop-foundation documentation overlay."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[2]
DELTA = ROOT / "scripts/validate_docs_parts/pre_authority_document_delta.inc"
V4 = ROOT / "scripts/validate_docs_parts/pre_authority_overlay_v4.inc"
BASE = "6d19701767edd8ee9c6487bfe7105ca7d3dc8a4e"


def git(repo, *args, index=None, stdin=None):
    env = None if index is None else {"GIT_INDEX_FILE": str(index)}
    return subprocess.run(("git", "-C", str(repo), *args), check=True, env=env,
                          input=stdin, stdout=subprocess.PIPE).stdout


def module():
    value = types.ModuleType("pre_authority_overlay_v4")
    value.__file__ = str(DELTA)
    exec(DELTA.read_text(encoding="utf-8"), value.__dict__)
    exec(V4.read_text(encoding="utf-8"), value.__dict__)
    return value


class PreAuthorityDocumentOverlayV4Tests(unittest.TestCase):
    def repo(self):
        directory = tempfile.TemporaryDirectory(dir="/srv/data")
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name) / "repo"
        subprocess.run(("git", "clone", "-q", "--shared", str(ROOT), str(repo)), check=True)
        git(repo, "checkout", "-q", "-B", "overlay-v4-test", BASE)
        git(repo, "config", "user.email", "test@example.invalid")
        git(repo, "config", "user.name", "Test")
        return repo

    def candidate(self, value, repo):
        index = repo / "candidate.index"
        git(repo, "read-tree", "HEAD", index=index)
        for path in value.OVERLAY_V4_DOCUMENT_PATHS | {
            value.OVERLAY_V4_SCHEMA_PATH, value.OVERLAY_V4_ARTIFACT_PATH,
        }:
            target = ROOT / path
            candidate = repo / path
            candidate.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, candidate)
            git(repo, "add", "-f", path, index=index)
        return index

    def test_upgrade_requires_exact_documents_lineage_and_v3_pins(self):
        value, repo = module(), self.repo()
        index = self.candidate(value, repo)
        self.assertEqual(value.select_documentation_mode(repo, index_file=index), "overlay_v4")
        value.validate_pre_authority_document_overlay_v4(repo, index_file=index)
        changed = git(repo, "hash-object", "-w", "--stdin", index=index, stdin=b"changed\n").decode().strip()
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{changed},docs/evil.md", index=index)
        with self.assertRaisesRegex(ValueError, "OVERLAY_V4_ADDITION_POLICY"):
            value.validate_pre_authority_document_overlay_v4(repo, index_file=index)

    def test_upgrade_rejects_deletion_replacement_and_frozen_pin_mutation(self):
        value, repo = module(), self.repo()
        index = self.candidate(value, repo)
        git(repo, "update-index", "--force-remove", "docs/adr/ADR-0026-promotion-and-release-authority.md", index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_DELTA_DELETION"):
            value.validate_pre_authority_document_overlay_v4(repo, index_file=index)
        index = self.candidate(value, repo)
        changed = git(repo, "hash-object", "-w", "--stdin", index=index, stdin=b"changed\n").decode().strip()
        git(repo, "update-index", "--add", "--cacheinfo", f"100644,{changed},docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V3.json", index=index)
        with self.assertRaisesRegex(ValueError, "OVERLAY_V4_V3_PIN"):
            value.validate_pre_authority_document_overlay_v4(repo, index_file=index)

    def test_upgrade_rejects_each_v1_v2_frozen_pin_mutation(self):
        value, repo = module(), self.repo()
        for path in (
            value.SCHEMA_PATH, value.OVERLAY_SCHEMA_PATH, value.OVERLAY_ARTIFACT_PATH,
        ):
            with self.subTest(path=path):
                index = self.candidate(value, repo)
                changed = git(repo, "hash-object", "-w", "--stdin", index=index, stdin=b"{}\n").decode().strip()
                git(repo, "update-index", "--add", "--cacheinfo", f"100644,{changed},{path}", index=index)
                with self.assertRaisesRegex(ValueError, "OVERLAY_V4_FROZEN_PIN"):
                    value.validate_pre_authority_document_overlay_v4(repo, index_file=index)

    def test_v4_admission_uses_exact_cas_transaction_and_receipt_flow(self):
        value, repo = module(), self.repo()
        transaction = "OVERLAY_V4_DESKTOP_FOUNDATION"
        changes = {path: (ROOT / path).read_bytes()
                   for path in value.OVERLAY_TRANSACTION_PATHS[transaction]}
        with tempfile.TemporaryDirectory(dir="/srv/data") as directory:
            manifest = Path(directory) / "v4-manifest.json"
            prepared = value.prepare_pre_authority_overlay_admission(
                repo, transaction, changes, manifest,
            )
            self.addCleanup(prepared["temporary_directory"].cleanup)
            candidate = value.commit_pre_authority_overlay_admission(
                repo, prepared, "overlay v4", prepared["manifest_sha256"], allow_commit=True,
            )
            self.assertEqual(value.admit_pre_authority_overlay_candidate(
                repo, prepared, candidate, prepared["manifest_sha256"],
                candidate["candidate_receipt_sha256"], manual_ref_admission=False,
            ), candidate)
            self.assertEqual(value.admit_pre_authority_overlay_candidate(
                repo, prepared, candidate, prepared["manifest_sha256"],
                candidate["candidate_receipt_sha256"], manual_ref_admission=True,
            ), candidate["candidate_commit_oid"])


if __name__ == "__main__":
    unittest.main()
