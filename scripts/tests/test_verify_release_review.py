import hashlib
import json
import subprocess

from scripts.tests.release_fixture_support import VerifyReleaseMixin
from scripts.tests.release_test_support import ReleaseTestCase, SUPPORTED_TARGET


class VerifyReleaseReviewTests(ReleaseTestCase, VerifyReleaseMixin):
    def test_unknown_destination_profile_revision_blocks_before_fixture_promotion(self) -> None:
        candidate = self.make_approved_candidate()
        rollback_path = candidate / "evidence" / "rollback-windows.json"
        rollback = json.loads(rollback_path.read_text())
        rollback["destination_profiles"][0]["revision"] = 999
        rollback_path.write_bytes(json.dumps(rollback, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "rollback")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_upgrade_source_artifact_must_match_immutable_source_manifest(self) -> None:
        candidate = self.make_approved_candidate()
        upgrade_path = candidate / "evidence" / "upgrade-macos.json"
        upgrade = json.loads(upgrade_path.read_text())
        upgrade["source_artifact_sha256"] = "0" * 64
        upgrade_path.write_bytes(json.dumps(upgrade, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "upgrade")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_rollback_source_profile_must_match_immutable_source_manifest(self) -> None:
        candidate = self.make_approved_candidate()
        rollback_path = candidate / "evidence" / "rollback-linux.json"
        rollback = json.loads(rollback_path.read_text())
        rollback["source_profiles"][0]["revision"] = 999
        rollback_path.write_bytes(json.dumps(rollback, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "rollback")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_conflicting_source_profile_digest_for_same_name_and_revision_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        source_path = candidate / "evidence" / "source-candidate.json"
        source = json.loads(source_path.read_text())
        duplicate = dict(source["profiles"][0])
        duplicate["sha256"] = "0" * 64
        source["profiles"].append(duplicate)
        source_path.write_bytes(json.dumps(source, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        source_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        for evidence in manifest["evidence"]:
            if evidence["kind"] in {"fresh-install", "upgrade", "rollback"}:
                path = candidate / evidence["uri"].split(f"candidate://{candidate.name}/", 1)[1]
                payload = json.loads(path.read_text())
                payload["source_candidate_manifest_sha256"] = source_digest
                payload["source_profiles"] = source["profiles"]
                path.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                evidence["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_fixture_only_structural_candidate_preserves_source_and_candidate_bytes(self) -> None:
        candidate = self.make_approved_candidate()
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report, {"blocked_gate_ids": [], "status": "fixture-verified"})
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_final_review_with_declared_conflict_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review["conflict_declaration"] = "employer-conflict"
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_final_review_without_security_and_reliability_coverage_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review["role"] = "reliability"
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_normalized_final_reviewer_owner_self_review_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review["reviewer_identity"] = "  OWNER-A  "
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_unicode_normalized_final_reviewer_owner_self_review_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        self.assertEqual(
            self.verify_json(candidate, fixture_only=True),
            {"blocked_gate_ids": [], "status": "fixture-verified"},
        )
        final_review_path = candidate / "evidence" / "independent-final-review.json"
        final_review = json.loads(final_review_path.read_text())
        final_review["reviewer_identity"] = "jo\u0308hn"
        final_review_path.write_bytes(
            json.dumps(final_review, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        owner_approval_path = candidate / "evidence" / "owner-approval.json"
        owner_approval = json.loads(owner_approval_path.read_text())
        owner_approval["owner_identity"] = "\u2003JÖHN\u2003"
        owner_approval_path.write_bytes(
            json.dumps(owner_approval, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")
        self.refresh_candidate(candidate, manifest, "owner-approval")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_combined_final_review_bypass_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review.update({
            "conflict_declaration": "employer-conflict",
            "reviewer_identity": " Owner-A ",
            "role": "reliability",
        })
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_source_revision_must_match_checked_out_head(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["candidate"]["source_revision"] = "0" * 40
        self.write_manifest(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("source-integrity", report["blocked_gate_ids"])

    def test_unstaged_tracked_source_cannot_verify(self) -> None:
        candidate = self.make_approved_candidate()
        (self.root / "LICENSE").write_text("dirty source\n", encoding="utf-8")

        report = self.verify_json(candidate)

        self.assertIn("source-clean", report["blocked_gate_ids"])

    def test_staged_tracked_source_cannot_verify(self) -> None:
        candidate = self.make_approved_candidate()
        (self.root / "LICENSE").write_text("staged source\n", encoding="utf-8")
        subprocess.run(["git", "add", "LICENSE"], cwd=self.root, check=True)

        report = self.verify_json(candidate)

        self.assertIn("source-clean", report["blocked_gate_ids"])

    def test_empty_actual_hosted_runner_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["candidate"]["qualification_lanes"][0]["hosted_execution_slots"][0]["hosted_runner"] = {}
        self.write_manifest(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_reused_platform_artifact_binding_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["platforms"][1]["artifact_sha256"] = manifest["platforms"][0]["artifact_sha256"]
        self.write_manifest(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_cross_os_target_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["platforms"][0]["target"] = SUPPORTED_TARGET
        self.write_manifest(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_duplicate_evidence_identity_with_divergent_bytes_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        duplicate = next(record for record in manifest["evidence"] if record["kind"] == "advisory").copy()
        duplicate_path = candidate / "evidence" / "duplicate-advisory.json"
        duplicate_path.write_bytes(b'{"different":true}\n')
        duplicate["uri"] = f"candidate://{candidate.name}/evidence/duplicate-advisory.json"
        duplicate["sha256"] = hashlib.sha256(duplicate_path.read_bytes()).hexdigest()
        manifest["evidence"].append(duplicate)
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("manifest", report["blocked_gate_ids"])
