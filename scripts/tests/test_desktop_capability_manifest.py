"""Structural and semantic regression tests for the Desktop v1 registry."""

import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
from contextlib import redirect_stdout

from scripts.tests.desktop_capability_manifest_support import (
    CAPABILITY_SCHEMA,
    PROFILE,
    PROFILE_DIGEST,
    ROOT,
    STATUS,
    STATUS_SCHEMA,
    definition,
    load_json_no_duplicates,
    status,
    status_with_track_stages,
    validate_track_stages,
)


class DesktopCapabilityManifestTests(unittest.TestCase):
    def test_schema_rejects_truncated_track_stages(self) -> None:
        schema = load_json_no_duplicates(CAPABILITY_SCHEMA)
        definition = load_json_no_duplicates(PROFILE)
        stages = definition["capabilities"][0]["tracks"][0]["stages"][:-1]

        with self.assertRaisesRegex(ValueError, "minItems"):
            validate_track_stages(schema, stages)

    def test_repository_artifacts_are_closed_and_weighted(self) -> None:
        capability_schema = load_json_no_duplicates(CAPABILITY_SCHEMA)
        status_schema = load_json_no_duplicates(STATUS_SCHEMA)
        definition = load_json_no_duplicates(PROFILE)
        status = load_json_no_duplicates(STATUS)

        self.assertEqual(capability_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(capability_schema["additionalProperties"])
        self.assertTrue(capability_schema["required"])
        self.assertEqual(status_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(status_schema["additionalProperties"])
        self.assertTrue(status_schema["required"])
        self.assertEqual(definition["schema_version"], "desktop-v1-capabilities.v1")
        self.assertEqual(sum(c["weight_bps"] for c in definition["capabilities"]), 10_000)
        self.assertEqual(
            PROFILE_DIGEST.read_text(encoding="utf-8"),
            f"sha256:{hashlib.sha256(PROFILE.read_bytes()).hexdigest()}\n",
        )
        self.assertNotIn("current_stage", status)
        self.assertNotIn("score_bps", status)
        self.assertNotIn("fully_qualified", status)
        self.assertEqual(status["schema_version"], "desktop-v1-capability-status.v1")
        self.assertTrue(all(row["disposition"] == "not_recorded" for row in status["gates"]))
        self.assertTrue(all(row["disposition"] == "blocked" for row in status["capabilities"]))

    def test_definition_rejects_unknown_references_and_dependency_cycles(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_definition

        value = definition()
        value["capabilities"][0]["requirement_ids"] = ["REQ-UNKNOWN"]
        errors = validate_definition(value, {"REQ-PRD-005"}, {"SA-014"})
        self.assertIn("DEFINITION_UNKNOWN_REQUIREMENT:CAP-RTS:REQ-UNKNOWN", errors)

        value = definition()
        value["capabilities"][0]["build_requires"].append("CAP-PJW")
        errors = validate_definition(value, {item for capability in value["capabilities"] for item in capability["requirement_ids"]}, {item for capability in value["capabilities"] for item in capability["abuse_case_ids"]})
        self.assertIn("DEFINITION_DEPENDENCY_CYCLE", errors)

    def test_definition_rejects_non_contiguous_stages(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_definition

        value = definition()
        value["capabilities"][0]["tracks"][0]["stages"][2]["stage"] = 70
        errors = validate_definition(value, {item for capability in value["capabilities"] for item in capability["requirement_ids"]}, {item for capability in value["capabilities"] for item in capability["abuse_case_ids"]})
        self.assertIn("DEFINITION_NONCONTIGUOUS_STAGES:CAP-RTS:runtime-session", errors)

    def test_status_rejects_missing_platform_and_reused_artifact(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_status

        value = status()
        value["platforms"].pop()
        self.assertIn("STATUS_MISSING_PLATFORM:LINUX-UBUNTU-22-04-X86-64", validate_status(definition(), value))

        value = status_with_track_stages((40, 0, 0))
        value["gates"][1]["evidence_ref"] = value["gates"][0]["evidence_ref"]
        self.assertIn("STATUS_REUSED_EVIDENCE:GATE-CONTRACT-SCHEMA", validate_status(definition(), value))

    def test_status_rejects_compile_only_or_stub_evidence(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_status

        value = status_with_track_stages((20, 0, 0))
        value["gates"][0]["evidence_ref"] = "compile-only-stub"
        value["evidence_refs"] = [{"id": "compile-only-stub", "sha256": "1" * 64}]
        self.assertIn("STATUS_UNTRUSTED_EVIDENCE:GATE-CONTRACT-SCHEMA", validate_status(definition(), value))

    def test_evaluate_uses_lowest_track_stage_and_never_qualifies_without_binding(self) -> None:
        from scripts.desktop.capability_manifest_impl.scoring import QualificationContext, evaluate

        definition_value = definition()
        definition_value["capabilities"] = [item for item in definition_value["capabilities"] if item["id"] == "CAP-SET"]
        status_value = status_with_track_stages((100, 80, 100))
        verified = tuple(row["gate_id"] for row in status_value["gates"] if row["disposition"] == "verified")
        qualification = QualificationContext(status_value["canonical_source_content_sha256"], "candidate", True, "1" * 64, verified)
        evaluation = evaluate(definition_value, status_value, qualification)
        self.assertEqual(evaluation.capability_stages, (("CAP-SET", 80),))
        self.assertFalse(evaluation.fully_qualified)

    def test_evaluate_ignores_forged_computed_status_fields(self) -> None:
        from scripts.desktop.capability_manifest_impl.scoring import evaluate

        value = status()
        value["score_bps"] = 10_000
        value["fully_qualified"] = True
        evaluation = evaluate(definition(), value)
        self.assertEqual(evaluation.score_bps, 0)
        self.assertFalse(evaluation.fully_qualified)

    def test_repository_rejects_raw_definition_digest_mismatch(self) -> None:
        from scripts.desktop.capability_manifest_impl.io import has_raw_sha256

        self.assertFalse(has_raw_sha256(PROFILE.read_bytes(), "sha256:" + "0" * 64 + "\n"))
        self.assertEqual(PROFILE_DIGEST.read_text(encoding="utf-8").strip().split(":", 1)[1], hashlib.sha256(PROFILE.read_bytes()).hexdigest())

    def test_closed_validation_rejects_omitted_schema_fields_and_contract_wave(self) -> None:
        from scripts.desktop.capability_manifest_impl.validation import validate_definition, validate_status

        value = definition()
        value["capabilities"][0]["tracks"][0]["stage_profile"] = "invalid"
        value["capabilities"][0]["qualification_requires"] = ["FOUND-99"]
        errors = validate_definition(value, {item for capability in value["capabilities"] for item in capability["requirement_ids"]}, {item for capability in value["capabilities"] for item in capability["abuse_case_ids"]})
        self.assertIn("DEFINITION_TRACK_VALUE:CAP-RTS:runtime-session", errors)
        self.assertIn("DEFINITION_UNKNOWN_QUALIFICATION:CAP-RTS:FOUND-99", errors)

        value = status()
        value["recorded_at"] = 1
        value["selector_list_sha256"] = "not-a-digest"
        value["contract"] = None
        errors = validate_status(definition(), value)
        self.assertIn("STATUS_RECORDED_AT", errors)
        self.assertIn("STATUS_SELECTOR_DIGEST", errors)
        self.assertIn("STATUS_CONTRACT", errors)

    def test_verifier_requires_exact_gh_arguments_and_authenticated_bindings(self) -> None:
        from scripts.desktop.capability_manifest_impl.io import verify_attestation

        evidence = self._evidence()
        with tempfile.TemporaryDirectory(dir=ROOT / ".superpowers") as directory:
            subject = Path(directory) / "gate.json"
            subject.write_text(json.dumps(evidence), encoding="utf-8")
            bundle = Path(f"{subject}.intoto.jsonl")
            bundle.write_text("bundle", encoding="utf-8")
            predicate = dict(evidence)
            statement = {"subject": [{"digest": {"sha256": hashlib.sha256(subject.read_bytes()).hexdigest()}}], "predicate": predicate}
            output = json.dumps({"verificationResult": {"statement": statement}})
            with patch("scripts.desktop.capability_manifest_impl.io.subprocess.run", return_value=CompletedProcess([], 0, output, "")) as run:
                result = verify_attestation(subject, bundle, self._policy(), "commit-a")
            self.assertEqual(result, predicate)
            self.assertEqual(run.call_args.args[0], ["gh", "attestation", "verify", str(subject), "--bundle", str(bundle), "--repo", "org/repo", "--signer-workflow", ".github/workflows/qualify.yml", "--source-ref", "refs/heads/release", "--source-digest", "commit-a", "--predicate-type", "https://slsa.dev/provenance/v1", "--no-public-good", "--format", "json"])

    def test_verifier_rejects_bad_result_shapes_and_each_evidence_binding(self) -> None:
        from scripts.desktop.capability_manifest_impl.io import verify_attestation

        evidence = self._evidence()
        with tempfile.TemporaryDirectory(dir=ROOT / ".superpowers") as directory:
            subject = Path(directory) / "gate.json"
            subject.write_text(json.dumps(evidence), encoding="utf-8")
            bundle = Path(f"{subject}.intoto.jsonl")
            bundle.write_text("bundle", encoding="utf-8")
            statement = {"subject": [{"digest": {"sha256": hashlib.sha256(subject.read_bytes()).hexdigest()}}], "predicate": evidence}
            cases = ("", "{}", json.dumps({"verificationResult": {"statement": {**statement, "subject": []}}}))
            for output in cases:
                with self.subTest(output=output), patch("scripts.desktop.capability_manifest_impl.io.subprocess.run", return_value=CompletedProcess([], 0, output, "")):
                    self.assertIsNone(verify_attestation(subject, bundle, self._policy(), "commit-a"))

    def test_gate_predicate_rejects_each_required_binding_mutation(self) -> None:
        from scripts.desktop.capability_manifest import _gate_predicate

        evidence = self._evidence()
        with tempfile.TemporaryDirectory(dir=ROOT / ".superpowers") as directory:
            path = Path(directory) / "gate.json"; path.write_text(json.dumps(evidence), encoding="utf-8")
            status_value = status(); status_value.update({"canonical_source_content_sha256": "a" * 64, "definition_sha256": "b" * 64, "selector_list_sha256": "c" * 64, "toolchain_identity": evidence["toolchain_identity"], "runner_identity": evidence["runner_identity"]})
            row = {"gate_id": "GATE-CONTRACT-SCHEMA", "provenance": {"subject_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "predicate_sha256": hashlib.sha256(json.dumps(evidence, separators=(",", ":"), sort_keys=True).encode()).hexdigest()}}
            self.assertTrue(_gate_predicate(evidence, path, status_value, row))
            for key in ("canonical_source_content_sha256", "definition_sha256", "gate_id", "selector_list_sha256", "toolchain_identity", "runner_identity", "artifacts", "tests", "kind"):
                altered = dict(evidence); altered[key] = "wrong" if key not in {"artifacts", "tests"} else []
                self.assertFalse(_gate_predicate(altered, path, status_value, row))

    def test_verifier_fails_closed_for_missing_or_nonzero_gh(self) -> None:
        from scripts.desktop.capability_manifest_impl.io import verify_attestation

        with tempfile.TemporaryDirectory(dir=ROOT / ".superpowers") as directory:
            subject = Path(directory) / "gate.json"; subject.write_text("{}", encoding="utf-8"); bundle = Path(f"{subject}.intoto.jsonl")
            for result in (FileNotFoundError(), CompletedProcess([], 1, "", "failure")):
                with self.subTest(result=type(result).__name__), patch("scripts.desktop.capability_manifest_impl.io.subprocess.run", side_effect=result if isinstance(result, FileNotFoundError) else None, return_value=result if isinstance(result, CompletedProcess) else None):
                    self.assertIsNone(verify_attestation(subject, bundle, self._policy(), "commit-a"))

    def test_candidate_source_digest_excludes_only_evidence_and_dirty_product_paths(self) -> None:
        from scripts.desktop.capability_manifest_impl.io import canonical_source_content_digest, clean_source_paths, evidence_only_difference

        with tempfile.TemporaryDirectory(dir=ROOT / ".superpowers") as directory:
            root = Path(directory)
            for command in (("git", "init"), ("git", "config", "user.email", "test@example.invalid"), ("git", "config", "user.name", "Test")):
                subprocess.run(command, cwd=root, check=True, capture_output=True)
            (root / "product.txt").write_text("A", encoding="utf-8"); (root / "docs/evidence").mkdir(parents=True); (root / "docs/evidence/row.json").write_text("one", encoding="utf-8")
            subprocess.run(("git", "add", "."), cwd=root, check=True); subprocess.run(("git", "commit", "-m", "A"), cwd=root, check=True, capture_output=True); first = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=root, text=True).strip()
            (root / "product.txt").write_text("B", encoding="utf-8"); subprocess.run(("git", "commit", "-am", "B"), cwd=root, check=True, capture_output=True); second = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=root, text=True).strip()
            self.assertNotEqual(canonical_source_content_digest(root, first), canonical_source_content_digest(root, second)); self.assertFalse(evidence_only_difference(root, first, second))
            (root / "docs/evidence/row.json").write_text("two", encoding="utf-8"); subprocess.run(("git", "commit", "-am", "evidence"), cwd=root, check=True, capture_output=True); third = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=root, text=True).strip()
            self.assertEqual(canonical_source_content_digest(root, second), canonical_source_content_digest(root, third)); self.assertTrue(evidence_only_difference(root, second, third)); (root / "dirty.txt").write_text("x", encoding="utf-8"); self.assertFalse(clean_source_paths(root))

    def test_cli_rejects_missing_selected_status_and_unresolvable_source_ref(self) -> None:
        from scripts.desktop.capability_manifest import main

        output = io.StringIO()
        with redirect_stdout(output): self.assertEqual(main(["score", "--status", str(ROOT / "missing-status.json"), "--format", "json"]), 1)
        self.assertIn("REPOSITORY_READ_ERROR", output.getvalue())
        output = io.StringIO()
        with redirect_stdout(output): self.assertEqual(main(["validate", "--source-ref", "does-not-exist"]), 1)
        self.assertIn("REPOSITORY_READ_ERROR", output.getvalue())

    @staticmethod
    def _policy() -> dict[str, str]:
        return {"repository": "org/repo", "signer_workflow": ".github/workflows/qualify.yml", "source_ref": "refs/heads/release"}

    @staticmethod
    def _evidence() -> dict[str, object]:
        return {"schema_version": "desktop-v1-gate-evidence.v1", "kind": "functional", "gate_id": "GATE-CONTRACT-SCHEMA", "canonical_source_content_sha256": "a" * 64, "definition_sha256": "b" * 64, "selector_list_sha256": "c" * 64, "toolchain_identity": {"status": "recorded", "name": "python", "version": "1"}, "runner_identity": {"status": "recorded", "runner_id": "runner", "image_sha256": "d" * 64}, "artifacts": [{"sha256": "e" * 64}], "tests": [{"sha256": "f" * 64}]}


if __name__ == "__main__":
    unittest.main()
