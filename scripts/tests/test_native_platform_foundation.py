"""Fail-closed structural tests for the native platform foundation validator."""

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import scripts.desktop.native_platform_foundation as native_foundation
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
    _policy_from_env,
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

    def test_runner_trust_blocker_accepts_package_probe_and_rejects_gocoder_alias(self) -> None:
        from scripts.desktop.native_package_probe import preflight

        probe = preflight("ubuntu-22.04-x86_64", "target/release/bundle/deb/wrong.deb")
        self.assertEqual(probe["blocker_code"], "RUNNER_TRUST_UNVERIFIED")
        row = copy.deepcopy(baseline()["platforms"][-1])
        row["blocker_code"] = probe["blocker_code"]
        self.assertEqual(row_errors(row), [])
        row["blocker_code"] = "GOCODER_TRUST_UNVERIFIED"
        self.assertTrue(row_errors(row))

    def test_sourcecraft_policy_requires_exact_protected_binding(self) -> None:
        environment = {
            "SOURCECRAFT_CI": "true",
            "SOURCECRAFT_REPO_URL": "https://git@git.sourcecraft.dev/ryltsevmg/runne.git",
            "SOURCECRAFT_WORKFLOW": "desktop-qualification",
            "SOURCECRAFT_COMMIT_REF": "refs/tags/v1.0.0",
        }
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(_policy_from_env(), {
                "repository": environment["SOURCECRAFT_REPO_URL"],
                "workflow": environment["SOURCECRAFT_WORKFLOW"],
                "ref": environment["SOURCECRAFT_COMMIT_REF"],
            })
        for name in environment:
            with self.subTest(name=name), patch.dict(os.environ, {key: value for key, value in environment.items() if key != name}, clear=True):
                self.assertIsNone(_policy_from_env())
        with patch.dict(os.environ, {**environment, "SOURCECRAFT_REPO_URL": "https://git.sourcecraft.dev/attacker/repo.git"}, clear=True):
            self.assertIsNone(_policy_from_env())

    def test_external_verifier_is_fixed_and_missing_or_checkout_verifier_blocks(self) -> None:
        self.assertEqual(native_foundation.SOURCECRAFT_NATIVE_VERIFIER_PATH, Path("/opt/gocode/sourcecraft/bin/sourcecraft-attest-verify"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package, bundle = root / "Runne.deb", root / "attestation.json"
            package.write_bytes(b"package")
            bundle.write_text("{}", encoding="utf-8")
            candidate = Path(__file__).parents[1] / "desktop/sourcecraft_attestation.py"
            policy = {"repository": "https://git@git.sourcecraft.dev/ryltsevmg/runne.git", "workflow": "workflow", "ref": "refs/tags/v1.0.0"}
            self.assertIsNone(native_foundation._verify_bundle(package, bundle, policy, "a" * 40))
            self.assertNotEqual(candidate, native_foundation.SOURCECRAFT_NATIVE_VERIFIER_PATH)
            trusted = root / "sourcecraft-attest-verify"
            trusted.write_text("trusted", encoding="utf-8")
            trusted.chmod(0o755)
            result = {"verified": True, "subject_sha256": hashlib.sha256(package.read_bytes()).hexdigest(), "repository": policy["repository"], "workflow": policy["workflow"], "source_ref": policy["ref"], "source_digest": "a" * 40, "predicate": {"buildType": "sourcecraft/native"}}
            with patch.object(native_foundation, "SOURCECRAFT_NATIVE_VERIFIER_PATH", trusted), patch.object(native_foundation.subprocess, "run", return_value=CompletedProcess([], 0, json.dumps(result), "")) as run_command:
                self.assertEqual(native_foundation._verify_bundle(package, bundle, policy, "a" * 40), result)
            command = run_command.call_args.args[0]
            self.assertEqual(command[0], str(trusted))
            self.assertNotIn("gh", command)
            self.assertNotIn("sourcecraft_attestation.py", command)

    def test_provenance_accepts_only_verified_sourcecraft_result_bound_to_source(self) -> None:
        package_sha, evidence_sha, canonical = "a" * 64, "d" * 64, "b" * 64
        source_sha = "c" * 40
        policy = {"repository": "https://git@git.sourcecraft.dev/ryltsevmg/runne.git", "workflow": "desktop-qualification", "ref": "refs/tags/v1.0.0"}
        evidence = {"artifact_sha256": package_sha, "source_ref": source_sha, "canonical_source_content_sha256": canonical}
        def verified(subject_sha):
            return {"verified": True, "subject_sha256": subject_sha, "repository": policy["repository"], "workflow": policy["workflow"], "source_ref": policy["ref"], "source_digest": source_sha, "predicate": {"buildDefinition": {"buildType": "sourcecraft/native"}}}
        gate = {"package": verified(package_sha), "evidence": verified(evidence_sha)}
        self.assertEqual(verify_provenance_payload(evidence, package_sha, source_sha, policy, gate, evidence_sha), [])
        gate["evidence"]["source_digest"] = "0" * 40
        self.assertTrue(verify_provenance_payload(evidence, package_sha, source_sha, policy, gate, evidence_sha))

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
        schema = load_json(EVIDENCE_PATH.parents[1] / "schemas/desktop-v1-capability-status-v2.schema.json")
        blockers = schema["$defs"]["platform_status"]["properties"]["blocker_code"]["enum"]
        self.assertIn("RUNNER_TRUST_UNVERIFIED", blockers)
        self.assertNotIn("GOCODER_TRUST_UNVERIFIED", blockers)
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); rows = directory / "rows"; rows.mkdir()
            accepted = []
            for platform in MANDATORY_PLATFORMS:
                row = {"platform_id": platform, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED"}
                artifact = rows / platform; artifact.mkdir(); (artifact / "native-platform-row.json").write_text(json.dumps(row), encoding="utf-8"); accepted.append(row)
            lifecycle = directory / "lifecycle.json"; lifecycle.write_text(json.dumps({"verified": True, "platforms": list(MANDATORY_PLATFORMS), "rows": accepted}), encoding="utf-8")
            output = directory / "status.json"
            self.assertEqual(assemble_status(rows, lifecycle, ROOT_STATUS, output), 0)
            status = load_json(output)
            self.assertTrue(all(row["blocker_code"] in blockers for row in status["platforms"]))
            self.assertEqual(validate_status(definition, status), ())
            status["platforms"][0]["blocker_code"] = "GOCODER_TRUST_UNVERIFIED"
            self.assertNotIn(status["platforms"][0]["blocker_code"], blockers)
            self.assertTrue(validate_status(definition, status))

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
SOURCECRAFT_WORKFLOW = EVIDENCE_PATH.parents[2] / ".sourcecraft/ci.yaml"


class NativeQualificationWorkflowTests(unittest.TestCase):
    def test_sourcecraft_workflow_builds_the_canonical_macos_package_and_preserves_release_gate(self) -> None:
        workflow = SOURCECRAFT_WORKFLOW.read_text(encoding="utf-8")
        qualification = workflow[workflow.index("  desktop-qualification:"):]
        for required in (
            "qualification-policy",
            "qualification-native-macos",
            "qualification-evidence",
            "pnpm install --frozen-lockfile",
            "package_smoke.py --platform macos-14-arm64",
            "sourcecraft-native-qualification-controller",
            "needs: [qualification-policy]",
        ):
            self.assertIn(required, qualification)
        for removed in ("qualification-native-linux", "qualification-native-macos-x86_64", "qualification-native-windows"):
            self.assertNotIn(removed, qualification)

    def test_sourcecraft_workflow_binds_policy_and_external_evidence(self) -> None:
        workflow = SOURCECRAFT_WORKFLOW.read_text(encoding="utf-8")
        qualification = workflow[workflow.index("  desktop-qualification:"):]
        for required in (
            'test "$SOURCECRAFT_EVENT" = "manual"',
            "^refs/tags/v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$",
            'test "$SOURCECRAFT_COMMIT_SHA" = "$QUALIFICATION_CANDIDATE_SHA"',
            'test "$SOURCECRAFT_REPO_URL" = "https://git@git.sourcecraft.dev/ryltsevmg/runne.git"',
            "SOURCECRAFT_DESKTOP_ATTEST_REPOSITORY",
            "SOURCECRAFT_DESKTOP_ATTEST_WORKFLOW",
            "SOURCECRAFT_DESKTOP_ATTEST_SOURCE_REF",
            "SOURCECRAFT_DESKTOP_ATTEST_SIGNER",
            "/opt/gocode/sourcecraft/bin/sourcecraft-desktop-evidence-enforce",
        ):
            self.assertIn(required, qualification)
        policy = (EVIDENCE_PATH.parents[2] / ".sourcecraft/branches.yaml").read_text(encoding="utf-8")
        for required in ('target: tag', 'matches: "v*"', "prevent_creation", "prevent_update", "prevent_deletion"):
            self.assertIn(required, policy)
        for forbidden in ("GITHUB", "gh ", "actions/"):
            self.assertNotIn(forbidden, qualification)
        self.assertNotIn(".github/workflows", qualification)
        self.assertNotIn("SOURCECRAFT_DESKTOP_ATTEST_VERIFY_KEY", qualification)
if __name__ == "__main__":
    unittest.main()
