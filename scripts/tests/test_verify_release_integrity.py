import json

from scripts.tests.release_fixture_support import VerifyReleaseMixin
from scripts.tests.release_test_support import ReleaseTestCase


class VerifyReleaseIntegrityTests(ReleaseTestCase, VerifyReleaseMixin):
    def test_changed_archive_file_blocks_without_mutating_inputs(self) -> None:
        candidate = self.package_candidate()
        (candidate / "runne-daemon").write_bytes(b"altered archive bytes\n")
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("artifact-digest", report["blocked_gate_ids"])
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_malformed_checksum_blocks_without_mutating_inputs(self) -> None:
        candidate = self.package_candidate()
        (candidate / "checksums.sha256").write_text("not a checksum\n", encoding="utf-8")
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("checksums", report["blocked_gate_ids"])
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_checked_in_profile_digest_mismatch_blocks_without_mutating_inputs(self) -> None:
        candidate = self.package_candidate()
        (self.root / "docs" / "profiles" / "profile-a.digest").write_text(
            "sha256:" + "0" * 64 + "\n", encoding="utf-8"
        )
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("profile-integrity", report["blocked_gate_ids"])
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_missing_hosted_platform_evidence_is_explicitly_blocked(self) -> None:
        candidate = self.package_candidate()

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("hosted-platform-evidence", report["blocked_gate_ids"])

    def test_single_platform_assembled_package_is_structurally_accepted_and_blocked(self) -> None:
        candidate = self.package_candidate()

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertNotIn("manifest", report["blocked_gate_ids"])
        self.assertIn("hosted-platform-evidence", report["blocked_gate_ids"])

    def test_fixture_hosted_evidence_cannot_produce_production_verified(self) -> None:
        candidate = self.make_approved_candidate()

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("hosted-platform-evidence", report["blocked_gate_ids"])
        self.assertIn("approval-attestation", report["blocked_gate_ids"])

    def test_review_approval_replay_with_a_different_subject_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "owner-approval.json"
        review = json.loads(review_path.read_text())
        review["review_subject_digest"] = "0" * 64
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "owner-approval")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_final_review_attestation_cannot_be_reused_as_owner_approval(self) -> None:
        candidate = self.make_approved_candidate()
        final_review = json.loads((candidate / "evidence" / "independent-final-review.json").read_text())
        owner_path = candidate / "evidence" / "owner-approval.json"
        owner_approval = json.loads(owner_path.read_text())
        owner_approval["attestation"] = final_review["attestation"]
        owner_path.write_bytes(json.dumps(owner_approval, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "owner-approval")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_review_pending_packet_remains_valid_when_promoted_to_approved(self) -> None:
        candidate = self.make_approved_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        review_packet_path = candidate / "evidence" / "review-packet.json"
        review_packet = json.loads(review_packet_path.read_text())
        decision_records = [record for record in manifest["evidence"] if record["kind"] in {"independent-final-review", "owner-approval"}]
        decision_bytes = {
            record["kind"]: (candidate / record["uri"].split(f"candidate://{candidate.name}/", 1)[1]).read_bytes()
            for record in decision_records
        }
        for record in decision_records:
            (candidate / record["uri"].split(f"candidate://{candidate.name}/", 1)[1]).unlink()
        manifest["evidence"] = [record for record in manifest["evidence"] if record["kind"] not in {"independent-final-review", "owner-approval"}]
        manifest["qualification_state"] = "review-pending"
        self.refresh_candidate(candidate, manifest)

        pending_report = self.verify_json(candidate, fixture_only=True)

        self.assertNotIn("manifest", pending_report["blocked_gate_ids"])
        self.assertEqual(review_packet["review_subject_digest"], json.loads(review_packet_path.read_text())["review_subject_digest"])

        for record in decision_records:
            path = candidate / record["uri"].split(f"candidate://{candidate.name}/", 1)[1]
            path.write_bytes(decision_bytes[record["kind"]])
        manifest["evidence"].extend(decision_records)
        manifest["qualification_state"] = "approved"
        self.refresh_candidate(candidate, manifest)

        self.assertEqual(self.verify_json(candidate, fixture_only=True), {"blocked_gate_ids": [], "status": "fixture-verified"})

    def test_owner_approval_requires_rubric_and_attestation_subject_fields(self) -> None:
        candidate = self.make_approved_candidate()
        owner_path = candidate / "evidence" / "owner-approval.json"
        owner_approval = json.loads(owner_path.read_text())
        owner_approval.pop("rubric_version")
        owner_path.write_bytes(json.dumps(owner_approval, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "owner-approval")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_fixture_approval_requires_the_closed_fixture_issuer(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review["attestation"]["issuer"] = "untrusted-review-authority"
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_later_state_requires_assembled_records_for_each_platform(self) -> None:
        candidate = self.make_approved_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        manifest["evidence"] = [
            record for record in manifest["evidence"]
            if not (record["kind"] == "sbom" and record["platform"] == "windows")
        ]
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_compatibility_payload_cannot_masquerade_as_phase8_evidence(self) -> None:
        candidate = self.make_approved_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        phase8 = next(record for record in manifest["evidence"] if record["kind"] == "phase8-compatibility")
        compatibility = next(record for record in manifest["evidence"] if record["kind"] == "compatibility")
        phase8["uri"] = compatibility["uri"]
        phase8["sha256"] = compatibility["sha256"]
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("phase8-compatibility", report["blocked_gate_ids"])

    def test_compatibility_payload_cannot_masquerade_as_advisory_evidence(self) -> None:
        candidate = self.make_approved_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        advisory = next(record for record in manifest["evidence"] if record["kind"] == "advisory")
        compatibility = next(record for record in manifest["evidence"] if record["kind"] == "compatibility")
        advisory["uri"] = compatibility["uri"]
        advisory["sha256"] = compatibility["sha256"]
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_unsuccessful_supply_chain_payload_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        advisory_path = candidate / "evidence" / "advisory.json"
        advisory = json.loads(advisory_path.read_text())
        advisory["outcome"] = "failed"
        advisory_path.write_bytes(json.dumps(advisory, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "advisory")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_incomplete_compatibility_rows_are_explicitly_blocked(self) -> None:
        candidate = self.make_approved_candidate()
        compatibility_path = candidate / "evidence" / "compatibility.json"
        compatibility = json.loads(compatibility_path.read_text())
        compatibility["rows"].pop()
        compatibility_path.write_bytes(json.dumps(compatibility, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "compatibility")

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("compatibility", report["blocked_gate_ids"])

    def test_non_verified_compatibility_row_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        compatibility_path = candidate / "evidence" / "compatibility.json"
        compatibility = json.loads(compatibility_path.read_text())
        compatibility["rows"][0].update({"decision": "scope-v1", "disposition": "unsupported", "rationale": "not in fixture"})
        compatibility_path.write_bytes(json.dumps(compatibility, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "compatibility")

        report = self.verify_json(candidate)

        self.assertIn("compatibility", report["blocked_gate_ids"])

    def test_upgrade_payload_with_different_candidate_digest_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        upgrade_path = candidate / "evidence" / "upgrade-linux.json"
        upgrade = json.loads(upgrade_path.read_text())
        upgrade["candidate_digest"] = "0" * 64
        upgrade_path.write_bytes(json.dumps(upgrade, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "upgrade")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])
