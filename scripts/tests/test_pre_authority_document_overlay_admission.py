"""Exact temporary-index admission tests for overlay v2."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[2]
DELTA = ROOT / "scripts/validate_docs_parts/pre_authority_document_delta.inc"
ANCHOR = "f6d0b2d6a5ccdda83ed80f9d0daefa785b622266"
MIXED = "1ea5dec17c36488819194b1d6aa443d932593966"


def git(repo, *args):
    return subprocess.run(("git", "-C", str(repo), *args), check=True, stdout=subprocess.PIPE).stdout


def module():
    value = types.ModuleType("overlay_admission")
    value.__file__ = str(DELTA)
    exec(DELTA.read_text(encoding="utf-8"), value.__dict__)
    return value


class OverlayAdmissionTests(unittest.TestCase):
    def repo(self, revision=ANCHOR):
        directory = tempfile.TemporaryDirectory(dir="/srv/data")
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name) / "repo"
        subprocess.run(("git", "clone", "-q", "--shared", str(ROOT), str(repo)), check=True)
        git(repo, "checkout", "-q", "-B", "admission-test", revision)
        git(repo, "config", "user.email", "test@example.invalid")
        git(repo, "config", "user.name", "Test")
        return repo

    def changes(self, value, transaction):
        changes = {path: (ROOT / path).read_bytes() for path in value.OVERLAY_TRANSACTION_PATHS[transaction] if path not in value.OVERLAY_DELETIONS[transaction]}
        if transaction == "TASK_2":
            path, content = "docs/schemas/README.md", changes["docs/schemas/README.md"]
            oid = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
            base = git(ROOT, "ls-tree", ANCHOR, "--", path).decode().split()
            artifact = json.loads((ROOT / value.OVERLAY_ARTIFACT_PATH).read_text())
            artifact["records"].append({"operation": "replace", "change_id": "TASK_2", "path": path, "candidate_mode": "100644", "candidate_blob_oid": oid, "candidate_sha256": hashlib.sha256(content).hexdigest(), "base_mode": base[0], "base_blob_oid": base[2], "base_sha256": hashlib.sha256(git(ROOT, "cat-file", "blob", f"{ANCHOR}:{path}")).hexdigest(), "classification": "governed", "reason": None})
            artifact["records"].sort(key=lambda record: record["path"])
            changes[value.OVERLAY_ARTIFACT_PATH] = json.dumps(artifact).encode()
        return changes

    def prepare(self, value, repo, transaction):
        prepared = value.prepare_pre_authority_overlay_admission(repo, transaction, self.changes(value, transaction), repo.with_suffix(".manifest.json"))
        self.addCleanup(prepared["temporary_directory"].cleanup)
        return prepared

    def bootstrap(self, value, repo):
        prepared = self.prepare(value, repo, "OVERLAY_V2_BOOTSTRAP")
        candidate = value.commit_pre_authority_overlay_admission(repo, prepared, "bootstrap", prepared["manifest_sha256"], allow_commit=True)
        value.admit_pre_authority_overlay_candidate(repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=True)

    def test_prepare_and_exact_commit_tree_for_bootstrap_and_task2(self):
        value = module()
        for transaction in value.OVERLAY_TRANSACTION_PATHS:
            with self.subTest(transaction=transaction):
                repo = self.repo(MIXED if transaction == "OVERLAY_V3_REPAIR" else ANCHOR)
                if transaction == "TASK_2":
                    self.bootstrap(value, repo)
                prepared = self.prepare(value, repo, transaction)
                candidate = value.commit_pre_authority_overlay_admission(repo, prepared, "overlay", prepared["manifest_sha256"], allow_commit=True)
                manifest = value.strict_json(prepared["manifest_path"].read_bytes(), "bad")
                self.assertEqual(git(repo, "rev-parse", f"{candidate['candidate_commit_oid']}^{{tree}}").decode().strip(), manifest["candidate_tree_oid"])
                self.assertEqual(candidate["status"], "BLOCKED_AT_MANUAL_REF_ADMISSION")
                if transaction == "OVERLAY_V3_REPAIR":
                    self.assertEqual(value.admit_pre_authority_overlay_candidate(repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=True), candidate["candidate_commit_oid"])
                    directory = tempfile.TemporaryDirectory(dir="/srv/data")
                    self.addCleanup(directory.cleanup)
                    clean = Path(directory.name) / "clean"
                    subprocess.run(("git", "clone", "-q", "--shared", str(repo), str(clean)), check=True)
                    for command in (("python3", "scripts/validate-docs.py", "--strict"), ("python3", "scripts/desktop/validate-docs.py", "--strict")):
                        result = subprocess.run(command, cwd=clean, text=True, capture_output=True)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_prepare_rejects_partial_extra_operation_mode_and_content(self):
        value, repo = module(), self.repo()
        changes = self.changes(value, "OVERLAY_V2_BOOTSTRAP")
        changes.pop(next(iter(changes)))
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_PATHS", value.prepare_pre_authority_overlay_admission, repo, "OVERLAY_V2_BOOTSTRAP", changes, repo.with_suffix(".m"))
        changes = self.changes(value, "OVERLAY_V2_BOOTSTRAP")
        changes["docs/evil.md"] = b"evil\n"
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_PATHS", value.prepare_pre_authority_overlay_admission, repo, "OVERLAY_V2_BOOTSTRAP", changes, repo.with_suffix(".m"))
        changes = self.changes(value, "OVERLAY_V2_BOOTSTRAP")
        changes["docs/schemas/pre-authority-document-overlay-v2.schema.json"] = b"{}"
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_VALIDATION", value.prepare_pre_authority_overlay_admission, repo, "OVERLAY_V2_BOOTSTRAP", changes, repo.with_suffix(".m"))

    def test_v3_repair_requires_exact_atomic_diff(self):
        value, repo = module(), self.repo(MIXED)
        changes = self.changes(value, "OVERLAY_V3_REPAIR")
        changes.pop(next(iter(changes)))
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_PATHS", value.prepare_pre_authority_overlay_admission, repo, "OVERLAY_V3_REPAIR", changes, repo.with_suffix(".m"))
        changes = self.changes(value, "OVERLAY_V3_REPAIR")
        changes["docs/extra.md"] = b"extra\n"
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_PATHS", value.prepare_pre_authority_overlay_admission, repo, "OVERLAY_V3_REPAIR", changes, repo.with_suffix(".m"))

    def test_commit_and_admit_reject_mutation_flags_and_substitution(self):
        value, repo = module(), self.repo()
        prepared = self.prepare(value, repo, "OVERLAY_V2_BOOTSTRAP")
        parent = git(repo, "rev-parse", "HEAD").decode().strip()
        for flag in (1, "true", None):
            self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_COMMIT", value.commit_pre_authority_overlay_admission, repo, prepared, "x", prepared["manifest_sha256"], allow_commit=flag)
        candidate = value.commit_pre_authority_overlay_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        self.assertEqual(value.admit_pre_authority_overlay_candidate(repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=False), candidate)
        self.assertEqual(git(repo, "rev-parse", "HEAD").decode().strip(), parent)
        oid = value.git_bytes(repo, ["hash-object", "-w", "--stdin"], stdin=b"bad").decode().strip()
        value.git_bytes(repo, ["update-index", "--cacheinfo", f"100755,{oid},scripts/validate_docs_parts/pre_authority_overlay_v2.inc"], prepared["index_file"])
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_HEAD", value.admit_pre_authority_overlay_candidate, repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=False)
        Path(prepared["manifest_path"]).write_text("{}", encoding="utf-8")
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_MANIFEST", value.admit_pre_authority_overlay_candidate, repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=False)
        self.assertEqual(git(repo, "rev-parse", "HEAD").decode().strip(), parent)

    def test_admit_validates_parent_single_commit_and_cas(self):
        value, repo = module(), self.repo()
        prepared = self.prepare(value, repo, "OVERLAY_V2_BOOTSTRAP")
        candidate = value.commit_pre_authority_overlay_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        for flag in (1, "false"):
            self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_MANUAL", value.admit_pre_authority_overlay_candidate, repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=flag)
        tree = candidate["candidate_tree_oid"]
        other = git(repo, "commit-tree", tree, "-p", candidate["parent_head_oid"], "-m", "other").decode().strip()
        forged = dict(candidate, candidate_commit_oid=git(repo, "commit-tree", tree, "-p", candidate["parent_head_oid"], "-p", other, "-m", "x").decode().strip())
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_TREE", value.admit_pre_authority_overlay_candidate, repo, prepared, forged, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=False)
        git(repo, "commit", "--allow-empty", "-m", "race")
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_HEAD", value.admit_pre_authority_overlay_candidate, repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=True)
        repo = self.repo()
        prepared = self.prepare(value, repo, "OVERLAY_V2_BOOTSTRAP")
        candidate = value.commit_pre_authority_overlay_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        self.assertEqual(value.admit_pre_authority_overlay_candidate(repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=True), candidate["candidate_commit_oid"])
        self.assertEqual(git(repo, "rev-parse", "HEAD").decode().strip(), candidate["candidate_commit_oid"])
        repo = self.repo()
        prepared = self.prepare(value, repo, "OVERLAY_V2_BOOTSTRAP")
        candidate = value.commit_pre_authority_overlay_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        git(repo, "branch", "alternate")
        git(repo, "symbolic-ref", "HEAD", "refs/heads/alternate")
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_HEAD", value.admit_pre_authority_overlay_candidate, repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=False)

    def test_candidate_receipt_binds_exact_raw_commit(self):
        value, repo = module(), self.repo()
        prepared = self.prepare(value, repo, "OVERLAY_V2_BOOTSTRAP")
        candidate = value.commit_pre_authority_overlay_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        self.assertIn("candidate_receipt_sha256", candidate)
        other = subprocess.run(("git", "-C", str(repo), "commit-tree", candidate["candidate_tree_oid"], "-p", candidate["parent_head_oid"], "-m", "x"), check=True, stdout=subprocess.PIPE, env={**os.environ, "GIT_AUTHOR_NAME": "Other", "GIT_AUTHOR_EMAIL": "other@example.invalid", "GIT_COMMITTER_NAME": "Other", "GIT_COMMITTER_EMAIL": "other@example.invalid", "GIT_AUTHOR_DATE": "2001-01-01T00:00:00 +0000", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00 +0000"}).stdout.decode().strip()
        forged = dict(candidate, candidate_commit_oid=other, candidate_commit_raw_sha256=hashlib.sha256(value.git_bytes(repo, ["cat-file", "commit", other])).hexdigest())
        self.assertRaisesRegex(ValueError, "OVERLAY_ADMISSION_TREE", value.admit_pre_authority_overlay_candidate, repo, prepared, forged, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=False)

    def test_raw_diff_accepts_sha256_repository(self):
        value = module()
        directory = tempfile.TemporaryDirectory(dir="/srv/data")
        self.addCleanup(directory.cleanup)
        repo, index = Path(directory.name) / "sha256", Path(directory.name) / "candidate.index"
        created = subprocess.run(("git", "init", "-q", "--object-format=sha256", str(repo)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if created.returncode:
            self.skipTest("git lacks sha256 repository support")
        empty = git(repo, "mktree").decode().strip()
        oid = subprocess.run(("git", "-C", str(repo), "hash-object", "-w", "--stdin"), input=b"sha256\n", check=True, stdout=subprocess.PIPE).stdout.decode().strip()
        value.git_bytes(repo, ["read-tree", empty], index)
        value.git_bytes(repo, ["update-index", "--add", "--cacheinfo", f"100644,{oid},docs/new.md"], index)
        record = value._overlay_raw_diff(repo, index, empty)["docs/new.md"]
        self.assertEqual(value._oid_width(repo), 64)
        self.assertEqual((record["old_oid"], record["new_oid"]), ("0" * 64, oid))

    def test_post_cas_symbolic_head_drift_is_admitted(self):
        value, repo = module(), self.repo()
        prepared = self.prepare(value, repo, "OVERLAY_V2_BOOTSTRAP")
        candidate = value.commit_pre_authority_overlay_admission(repo, prepared, "x", prepared["manifest_sha256"], allow_commit=True)
        original = value.git_bytes
        def switched(directory, args, index_file=None, stdin=None):
            result = original(directory, args, index_file, stdin)
            if args[:1] == ["update-ref"]:
                git(repo, "branch", "alternate", candidate["candidate_commit_oid"])
                git(repo, "symbolic-ref", "HEAD", "refs/heads/alternate")
                advanced = git(repo, "commit-tree", candidate["candidate_tree_oid"], "-p", candidate["candidate_commit_oid"], "-m", "external advance").decode().strip()
                git(repo, "update-ref", candidate["ref"], advanced, candidate["candidate_commit_oid"])
                self.advanced = advanced
            return result
        value.git_bytes = switched
        self.assertEqual(value.admit_pre_authority_overlay_candidate(repo, prepared, candidate, prepared["manifest_sha256"], candidate["candidate_receipt_sha256"], manual_ref_admission=True), candidate["candidate_commit_oid"])
        self.assertEqual(git(repo, "rev-parse", "refs/heads/admission-test").decode().strip(), self.advanced)


if __name__ == "__main__":
    unittest.main()
