"""Fail-closed structural tests for the native platform foundation validator."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.native_platform_foundation import (
    EVIDENCE_PATH,
    ALLOWED_BLOCKERS,
    MANDATORY_PLATFORMS,
    load_json,
    row_errors,
    validate_evidence,
    verify_provenance_errors,
    build_row,
    assemble_status,
    verify_provenance_payload,
)


def baseline() -> dict:
    return load_json(EVIDENCE_PATH)


class NativePlatformFoundationTests(unittest.TestCase):
    def test_baseline_evidence_validates(self) -> None:
        self.assertEqual(validate_evidence(baseline()), [])

    def test_baseline_keeps_every_platform_blocked(self) -> None:
        for row in baseline()["platforms"]:
            self.assertEqual(row["disposition"], "blocked")
            self.assertIsNone(row["artifact_sha256"])

    def test_mandatory_platform_matrix_required(self) -> None:
        evidence = baseline()
        evidence["platforms"] = evidence["platforms"][:3]
        self.assertTrue(validate_evidence(evidence))

    def test_unknown_platform_rejected(self) -> None:
        row = copy.deepcopy(baseline()["platforms"][0])
        row["platform_id"] = "FREEBSD-13-X86-64"
        self.assertTrue(row_errors(row))

    def test_blocked_row_with_generic_blocker_rejected(self) -> None:
        row = copy.deepcopy(baseline()["platforms"][0])
        row["blocker_code"] = "EVIDENCE_NOT_RECORDED"
        self.assertTrue(row_errors(row))

    def test_verified_row_without_full_evidence_rejected(self) -> None:
        row = copy.deepcopy(baseline()["platforms"][0])
        row["disposition"] = "verified"
        row["blocker_code"] = None
        errors = row_errors(row)
        self.assertTrue(errors)
        self.assertTrue(any("missing" in error for error in errors))

    def test_simulated_secure_store_probe_rejected(self) -> None:
        row = copy.deepcopy(baseline()["platforms"][0])
        row["disposition"] = "verified"
        row["blocker_code"] = None
        row["source_sha256"] = "a" * 64
        row["artifact_sha256"] = "b" * 64
        row["runner"] = {"runner_id": "r1", "image_sha256": "c" * 64, "instance_id": "i1"}
        row["packaged_executable"] = {"identity_sha256": "d" * 64, "signing_identity": "Team ID"}
        row["secure_store_probe"] = {"status": "verified", "detail": "simulated Keychain"}
        row["protected_launch_probe"] = {"status": "verified", "detail": "ok"}
        row["provenance"] = {"subject_sha256": "e" * 64, "predicate_sha256": "f" * 64}
        errors = row_errors(row)
        self.assertTrue(any("simulated" in error for error in errors))

    def test_ad_hoc_signing_identity_rejected(self) -> None:
        row = copy.deepcopy(baseline()["platforms"][0])
        row["disposition"] = "verified"
        row["blocker_code"] = None
        row["source_sha256"] = "a" * 64
        row["artifact_sha256"] = "b" * 64
        row["runner"] = {"runner_id": "r1", "image_sha256": "c" * 64, "instance_id": "i1"}
        row["packaged_executable"] = {"identity_sha256": "d" * 64, "signing_identity": "ad-hoc"}
        row["secure_store_probe"] = {"status": "verified", "detail": "ok"}
        row["protected_launch_probe"] = {"status": "verified", "detail": "ok"}
        row["provenance"] = {"subject_sha256": "e" * 64, "predicate_sha256": "f" * 64}
        errors = row_errors(row)
        self.assertTrue(any("signing" in error for error in errors))

    def test_verified_row_requires_measured_runner_image(self) -> None:
        row = copy.deepcopy(baseline()["platforms"][0])
        row["disposition"] = "verified"
        row["blocker_code"] = None
        row["source_sha256"] = "a" * 64
        row["artifact_sha256"] = "b" * 64
        row["runner"] = {"runner_id": "r1", "image_sha256": None, "instance_id": "i1"}
        row["packaged_executable"] = {"identity_sha256": "d" * 64, "signing_identity": "Team ID"}
        row["secure_store_probe"] = {"status": "verified", "detail": "ok"}
        row["protected_launch_probe"] = {"status": "verified", "detail": "ok"}
        row["provenance"] = {"subject_sha256": "e" * 64, "predicate_sha256": "f" * 64}
        errors = row_errors(row)
        self.assertTrue(any("runner" in error for error in errors))

    def test_verified_macos_row_requires_staged_daemon_and_notarization(self) -> None:
        row = copy.deepcopy(baseline()["platforms"][0])
        row.update(disposition="verified", blocker_code=None, source_sha256="a" * 64, artifact_sha256="b" * 64)
        row["runner"] = {"runner_id": "r1", "image_sha256": "c" * 64, "boot_measurement_sha256": "d" * 64, "instance_id": "i1", "job_id": "j1"}
        row["packaged_executable"] = {"identity_sha256": "e" * 64, "signing_identity": "Developer ID Application: GOCODE"}
        row["secure_store_probe"] = {"status": "verified", "detail": "native Keychain writer reader and third-process denial"}
        row["protected_launch_probe"] = {"status": "verified", "detail": "packaged relaunch"}
        row["provenance"] = {"subject_sha256": "f" * 64, "predicate_sha256": "0" * 64}
        errors = row_errors(row)
        self.assertTrue(any("staged daemon" in error or "notarization" in error for error in errors))

    def test_local_provenance_never_verifies(self) -> None:
        errors = verify_provenance_errors("refs/heads/main")
        self.assertTrue(errors)
        self.assertTrue(any("RUNNER_TRUST_UNVERIFIED" in error for error in errors))

    def test_blocker_vocabulary_is_specific(self) -> None:
        for platform in MANDATORY_PLATFORMS:
            self.assertIn(platform, ALLOWED_BLOCKERS)
            self.assertTrue(ALLOWED_BLOCKERS[platform])

    def test_provenance_rejects_self_authored_or_wrong_policy_bindings(self) -> None:
        package_sha = "a" * 64
        evidence = {"artifact_sha256": package_sha, "source_ref": "commit-1", "canonical_source_content_sha256": "b" * 64,
                    "provenance": {"issuer": "https://token.actions.githubusercontent.com", "repository": "gocode/repo",
                                   "workflow": ".github/workflows/desktop-native-qualification.yml", "ref": "refs/heads/release",
                                   "subject_sha256": package_sha, "predicate_sha256": "c" * 64}}
        policy = {"issuer": "https://token.actions.githubusercontent.com", "repository": "gocode/repo",
                  "workflow": ".github/workflows/desktop-native-qualification.yml", "ref": "refs/heads/release"}
        self.assertTrue(verify_provenance_payload(evidence, package_sha, "commit-1", policy, {"subject_sha256": package_sha, "predicate_sha256": "c" * 64}))
        evidence["provenance"]["repository"] = "attacker/repo"
        self.assertTrue(verify_provenance_payload(evidence, package_sha, "commit-1", policy, {"subject_sha256": package_sha, "predicate_sha256": "c" * 64}))

    def test_provenance_accepts_only_verified_sigstore_statement_bound_to_source(self) -> None:
        package_sha, evidence_sha, canonical = "a" * 64, "d" * 64, "b" * 64
        policy = {"issuer": "https://token.actions.githubusercontent.com", "repository": "gocode/repo", "workflow": ".github/workflows/desktop-native-qualification.yml", "ref": "refs/heads/release"}
        evidence = {"artifact_sha256": package_sha, "source_ref": "commit-1", "canonical_source_content_sha256": canonical}
        def verified():
            statement = {"subject": [{"digest": {"sha256": package_sha}}, {"digest": {"sha256": evidence_sha}}], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildDefinition": {"externalParameters": {"workflow": {"repository": f"https://github.com/{policy['repository']}", "path": policy["workflow"], "ref": policy["ref"]}}, "resolvedDependencies": [{"digest": {"gitCommit": "commit-1"}}], "internalParameters": {"github": {"runner_environment": "github-hosted"}}}}}
            return [{"verificationResult": {"statement": statement}}]
        gate = {"package": verified(), "evidence": verified()}
        self.assertEqual(verify_provenance_payload(evidence, package_sha, "commit-1", policy, gate, evidence_sha), [])
        gate["evidence"][0]["verificationResult"]["statement"]["subject"].append({"digest": {"sha256": "0" * 64}})
        self.assertTrue(verify_provenance_payload(evidence, package_sha, "commit-1", policy, gate, evidence_sha))

    def test_build_row_requires_verified_attestation_result_not_raw_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); probe = directory / "probe.json"; bundle = directory / "bundle.json"; output = directory / "row.json"
            probe.write_text(json.dumps({"platform_id": "MACOS-13-ARM64", "blocker_code": "RUNNER_TRUST_UNVERIFIED"}), encoding="utf-8")
            bundle.write_text(json.dumps({"subject_sha256": "a" * 64}), encoding="utf-8")
            self.assertEqual(build_row(probe, bundle, output), 1)

    def test_build_row_requires_a_nonempty_gate_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            probe = directory / "probe.json"; gate = directory / "gate.json"; output = directory / "row.json"
            probe.write_text(json.dumps({"platform_id": "MACOS-13-ARM64", "blocker_code": "MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED"}), encoding="utf-8")
            gate.write_text("", encoding="utf-8")
            self.assertEqual(build_row(probe, gate, output), 1)

    def test_assemble_status_requires_complete_unique_rows_and_verified_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); rows = directory / "rows"; rows.mkdir()
            for platform in MANDATORY_PLATFORMS[:3]:
                (rows / f"{platform}.json").write_text(json.dumps({"platform_id": platform, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED"}), encoding="utf-8")
            lifecycle = directory / "lifecycle.json"; lifecycle.write_text(json.dumps({"verified": True, "platforms": list(MANDATORY_PLATFORMS), "rows": [{"platform_id": platform, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED"} for platform in MANDATORY_PLATFORMS]}), encoding="utf-8")
            output = directory / "status.json"
            self.assertEqual(assemble_status(rows, lifecycle, ROOT_STATUS, output), 1)

    def test_assemble_status_preserves_specific_native_blockers_in_v2_status(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_status
        definition = load_json(EVIDENCE_PATH.parents[1] / "profiles/desktop-v1-capabilities-v1.json")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); rows = directory / "rows"; rows.mkdir()
            accepted = []
            for platform in MANDATORY_PLATFORMS:
                row = {"platform_id": platform, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED"}
                artifact = rows / platform; artifact.mkdir(); (artifact / "native-platform-row.json").write_text(json.dumps(row), encoding="utf-8"); accepted.append(row)
            lifecycle = directory / "lifecycle.json"; lifecycle.write_text(json.dumps({"verified": True, "platforms": list(MANDATORY_PLATFORMS), "rows": accepted}), encoding="utf-8")
            output = directory / "status.json"
            self.assertEqual(assemble_status(rows, lifecycle, ROOT_STATUS, output), 0)
            self.assertEqual(validate_status(definition, load_json(output)), ())

    def test_assemble_status_reads_only_downloaded_row_files_and_binds_lifecycle_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); rows = directory / "rows"; rows.mkdir()
            accepted = []
            for platform in MANDATORY_PLATFORMS:
                artifact = rows / f"native-row-{platform}"; artifact.mkdir()
                row = {"platform_id": platform, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED"}
                (artifact / "native-platform-row.json").write_text(json.dumps(row), encoding="utf-8")
                (artifact / "native-package-verified-attestation.json").write_text(json.dumps({"verified": True}), encoding="utf-8")
                accepted.append(row)
            lifecycle = directory / "lifecycle.json"; lifecycle.write_text(json.dumps({"verified": True, "platforms": list(MANDATORY_PLATFORMS), "rows": accepted}), encoding="utf-8")
            output = directory / "status.json"
            self.assertEqual(assemble_status(rows, lifecycle, ROOT_STATUS, output), 0)
            accepted[0]["blocker_code"] = "MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED"
            lifecycle.write_text(json.dumps({"verified": True, "platforms": list(MANDATORY_PLATFORMS), "rows": accepted}), encoding="utf-8")
            self.assertEqual(assemble_status(rows, lifecycle, ROOT_STATUS, output), 1)


ROOT_STATUS = EVIDENCE_PATH.parents[0] / "desktop-v1-capability-status-v2.json"


class NativeQualificationWorkflowTests(unittest.TestCase):
    def test_native_workflow_installs_dependencies_and_runs_protected_process_gate(self) -> None:
        workflow = (EVIDENCE_PATH.parents[2] / ".github/workflows/desktop-native-qualification.yml").read_text(encoding="utf-8")
        self.assertIn("pnpm install --frozen-lockfile", workflow)
        self.assertIn("cargo test -p gocode-daemon --test protected_bundled_runtime_process --locked", workflow)
        self.assertIn("macos-13-arm64", workflow)
        self.assertIn("windows-10-22h2-x86_64", workflow)

    def test_native_workflow_binds_protected_source_and_verified_attestation_output(self) -> None:
        workflow = (EVIDENCE_PATH.parents[2] / ".github/workflows/desktop-native-qualification.yml").read_text(encoding="utf-8")
        for required in ('test "${{ inputs.source_ref }}" = "$GITHUB_SHA"', 'ref: "${{ github.sha }}"', "persist-credentials: false", "GOCODE_NATIVE_PROVENANCE_ISSUER", "--bundle", "native-package-verified-attestation.json"):
            self.assertIn(required, workflow)
        self.assertNotIn("--native-secure-store-probe", workflow)
        self.assertIn("GOCODE_NATIVE_PROVENANCE_REF: ${{ vars.NATIVE_PROVENANCE_REF }}", workflow)
        self.assertNotIn("GOCODE_NATIVE_PROVENANCE_REF: ${{ github.ref }}", workflow)
        self.assertIn("verify-admission", workflow)
        self.assertIn("--runner-identity", workflow)
        for required in ("--cert-oidc-issuer", "NATIVE_RUNNER_CONTROL_PLANE_PUBLIC_ROOT_SHA256: ${{ vars.NATIVE_RUNNER_CONTROL_PLANE_PUBLIC_ROOT_SHA256 }}", "--trust-root-sha256", "--oidc-token-file", "--job-id \"$GITHUB_JOB\" --workflow-run-id \"$GITHUB_RUN_ID\"", "ACTIONS_ID_TOKEN_REQUEST_URL", "gocode-native-runner-control-plane", "id-token: write"):
            self.assertIn(required, workflow)


if __name__ == "__main__":
    unittest.main()
