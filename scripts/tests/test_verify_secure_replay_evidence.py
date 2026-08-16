from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).parents[2]
SCRIPT = pathlib.Path(__file__).parents[1] / "verify_secure_replay_evidence.py"


class VerifySecureReplayEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Evidence Test")
        self.path = self.root / "crates/demo.rs"
        self.path.parent.mkdir()
        self.path.write_text("base\n", encoding="utf-8")
        self.legacy = self.root / "docs/evidence/legacy.json"
        self.legacy.parent.mkdir(parents=True)
        self.legacy.write_text('{"legacy":true}\n', encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.output("rev-parse", "HEAD")
        self.original_blob = self.output("rev-parse", f"{self.base}:docs/evidence/legacy.json")
        self.path.write_text("snapshot\n", encoding="utf-8")
        self.legacy.write_text(self.recovered_json(), encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "snapshot")
        self.head = self.output("rev-parse", "HEAD")
        self.recovered_blob = self.output("rev-parse", f"{self.head}:docs/evidence/legacy.json")
        self.schema = self.root / "schema.json"
        self.schema.write_text('{"$id":"https://gocode.dev/schemas/secure-replay-evidence-v2.schema.json"}', encoding="utf-8")
        self.evidence = self.root / "docs/evidence/record-v2.json"
        self.write_record()

    def git(self, *args: str) -> None:
        subprocess.run(["git", "-C", str(self.root), *args], check=True)

    def output(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, text=True).stdout.strip()

    def claims(self) -> dict:
        return {"platform": {}, "toolchains": {}, "qualification": {}, "observedResults": [],
                "closureValidation": [], "coverage": {}, "securityReview": {}, "markerScan": {},
                "sensitiveDataPolicy": {}}

    def manifest(self, status: str = "present", digest: str | None = None) -> list[dict]:
        return [{"path": "crates/demo.rs", "status": status,
                 "sha256": digest if digest is not None else hashlib.sha256(b"snapshot\n").hexdigest()}]

    def recovered_json(self) -> str:
        record = {"subject": {"changedFileManifest": self.manifest()}, **self.claims()}
        return json.dumps(record)

    def record(self) -> dict:
        value = {
            "schemaVersion": 2, "evidenceId": "secure-replay-desktop-resume-v2", "recordedAt": "2026-07-30",
            "subject": {"sourceBaseCommit": self.base, "sourceHeadCommit": self.head,
                        "manifestAlgorithm": "git-tree-diff-sha256-v1",
                        "manifestSelfExcludedPath": "docs/evidence/legacy.json",
                        "changedFileManifest": self.manifest(), "contractProfileId": "gocode-ui-client/1",
                        "transportProfileId": "gocode-local-runtime/2", "contractBundleSha256": "0" * 64},
            "correctiveSuperseding": {"supersedesEvidenceId": "secure-replay-desktop-resume-v1",
                "originalEvidenceBlobSha1": self.original_blob,
                "originalEvidenceContentSha256": hashlib.sha256(b'{"legacy":true}\n').hexdigest(),
                "recoveredSnapshotCommit": self.head, "recoveredSnapshotEvidenceBlobSha1": self.recovered_blob},
            "canonicalJsonDigestAlgorithm": "canonical-json-sha256-v1", "canonicalJsonSha256": "", **self.claims()}
        value["canonicalJsonSha256"] = self.digest(value)
        return value

    def digest(self, value: dict) -> str:
        value = copy.deepcopy(value)
        value.pop("canonicalJsonSha256", None)
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def write_record(self, value: dict | None = None) -> None:
        self.evidence.write_text(json.dumps(value or self.record()), encoding="utf-8")

    def run_verifier(self, base: str | None = None, head: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["python3", str(SCRIPT), "--manifest", str(self.evidence), "--base", base or self.base,
                               "--head", head or self.head, "--schema", str(self.schema)], cwd=self.root,
                              capture_output=True, text=True)

    def test_accepts_snapshot_after_dirty_worktree_drift(self) -> None:
        self.path.write_text("dirty\n", encoding="utf-8")
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_wrong_head_hash_disposition_and_unlisted_path(self) -> None:
        self.path.write_text("later\n", encoding="utf-8")
        self.git("add", "crates/demo.rs")
        self.git("commit", "-qm", "later")
        self.assertIn("source commits", self.run_verifier(head=self.output("rev-parse", "HEAD")).stderr)
        record = self.record()
        record["subject"]["changedFileManifest"][0]["sha256"] = "0" * 64
        record["canonicalJsonSha256"] = self.digest(record)
        self.write_record(record)
        self.assertIn("SHA-256 mismatch", self.run_verifier().stderr)
        record = self.record()
        record["subject"]["changedFileManifest"][0].update(status="deleted", sha256=None)
        record["canonicalJsonSha256"] = self.digest(record)
        self.write_record(record)
        self.assertIn("expected deleted", self.run_verifier().stderr)
        record = self.record()
        record["subject"]["changedFileManifest"] = []
        record["canonicalJsonSha256"] = self.digest(record)
        self.write_record(record)
        self.assertIn("unlisted changed paths", self.run_verifier().stderr)

    def test_rejects_duplicate_keys_extra_exclusions_and_nonimmutable_references(self) -> None:
        self.evidence.write_text('{"schemaVersion":2,"schemaVersion":2}', encoding="utf-8")
        self.assertIn("duplicate key", self.run_verifier().stderr)
        record = self.record()
        record["subject"]["manifestSelfExcludedPath"] = "crates/demo.rs"
        record["canonicalJsonSha256"] = self.digest(record)
        self.write_record(record)
        self.assertIn("self-exclusion", self.run_verifier().stderr)
        for base, head in (("HEAD", self.head), (self.base[:8], self.head), (self.base, "HEAD"), (self.base, self.head[:8])):
            self.assertIn("full lowercase SHA-1", self.run_verifier(base, head).stderr)
        self.assertIn("required immutable Git object", self.run_verifier("0" * 40, self.head).stderr)

    def test_rejects_symlink_manifest_entry(self) -> None:
        blob = self.output("rev-parse", "HEAD:crates/demo.rs")
        self.git("update-index", "--add", "--cacheinfo", f"120000,{blob},crates/link")
        self.git("commit", "-qm", "symlink entry")
        self.assert_entry_is_not_regular_blob("crates/link")

    def test_rejects_gitlink_manifest_entry(self) -> None:
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.head},crates/gitlink")
        self.git("commit", "-qm", "gitlink entry")
        self.assert_entry_is_not_regular_blob("crates/gitlink")

    def assert_entry_is_not_regular_blob(self, path: str) -> None:
        head = self.output("rev-parse", "HEAD")
        record = self.record()
        record["subject"]["sourceHeadCommit"] = head
        record["correctiveSuperseding"]["recoveredSnapshotCommit"] = head
        record["subject"]["changedFileManifest"].append({"path": path, "status": "present", "sha256": "0" * 64})
        record["canonicalJsonSha256"] = self.digest(record)
        self.write_record(record)
        self.assertIn("regular blob", self.run_verifier(head=head).stderr)

    def test_pinned_v1_blob_and_v2_record_verify(self) -> None:
        v1 = ROOT / "docs/evidence/secure-replay-desktop-resume-v1.json"
        v2 = ROOT / "docs/evidence/secure-replay-desktop-resume-v2.json"
        schema = ROOT / "docs/schemas/secure-replay-evidence-v2.schema.json"
        legacy = subprocess.run(["python3", str(SCRIPT), "--manifest", str(v1), "--legacy-blob",
                                 "4713d84e94f68ae9c29de71325d4ecbd8d3096bb"], cwd=ROOT, capture_output=True, text=True)
        modern = subprocess.run(["python3", str(SCRIPT), "--manifest", str(v2), "--base",
                                 "d4dbabff8272118d99e6388dfbbf6df48b22faae", "--head",
                                 "6030bdbe77a3cd5dbcaeaa3bfd2d7bc3a5b4d3ca", "--schema", str(schema)], cwd=ROOT,
                                capture_output=True, text=True)
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        self.assertEqual(modern.returncode, 0, modern.stderr)


if __name__ == "__main__":
    unittest.main()
