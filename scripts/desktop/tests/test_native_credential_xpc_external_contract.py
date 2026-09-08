"""Structural contract for the independent DPK qualification authority."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "tools/sourcecraft-native-qualification"


class ExternalQualificationContractTests(unittest.TestCase):
    def test_checked_in_golden_vector_is_a_usable_test_only_subject(self) -> None:
        golden = json.loads((ROOT / "docs/golden/macos-xpc-service-external-contract-v1.json").read_text())
        self.assertTrue(golden["policy"]["test_only"])
        self.assertEqual(golden["policy"]["policy_id"], "runne/writer-qualification/v1")
        self.assertEqual(set(golden["files"]), {"macos-13-arm64.json", "expected-tuples.json", "artifact-manifest.json", "signed-envelope.json", "controller-conformance.json", "controller-lifecycle.json", "writer-transcript-v2.json", "service-admission.json", "sourcecraft-attestation.bundle"})

    def test_production_authority_has_fixed_paths_and_no_test_only_switch(self) -> None:
        verifier = (PACKAGE / "verifier.py").read_text(); policy = (PACKAGE / "policy.py").read_text()
        self.assertIn('PRIVATE_ROOT = Path("/private")', policy)
        self.assertIn('LEDGER_ROOT = PRIVATE_ROOT / "var/db/gocode/sourcecraft-native-qualification/replay"', policy)
        self.assertIn('if production and value["test_only"]:', policy)
        self.assertNotIn('add_argument("--policy"', verifier); self.assertNotIn('add_argument("--replay-ledger"', verifier)
        self.assertIn("verify_test_vector", verifier); self.assertIn("def verify_production", verifier)

    def test_contract_binds_full_native_subject_and_descriptor_inventory(self) -> None:
        verifier = (PACKAGE / "verifier.py").read_text(); contract = (PACKAGE / "contract.py").read_text(); codec = (PACKAGE / "codec.py").read_text()
        for field in ("artifact_manifest_sha256", "conformance_sha256", "writer_transcript_sha256", "service_admission_sha256"):
            self.assertIn(field, verifier)
        for receipt in ("writer-qualified-transcript/v2", "service-direct-admission/v1", "direct_admission"):
            self.assertIn(receipt, verifier)
        for field in ("service_code_identity_sha256", "deployment_sha256", "tuple_sha256", "terminal_exact_namespace_cleanup"):
            self.assertIn(field, contract)
        self.assertIn("os.open(part, flags, dir_fd=current)", codec); self.assertIn("O_NOFOLLOW", codec)

    def test_structural_gate_runs_external_contract_and_vector_tests(self) -> None:
        workflow = (ROOT / ".sourcecraft/ci.yaml").read_text()
        structural = workflow[workflow.index("- name: qualification-structural"):workflow.index("- name: qualification-native-linux")]
        self.assertIn("test_native_credential_xpc_external_contract", structural)
        self.assertIn("tools/sourcecraft-native-qualification/tests/test_conformance.py", structural)
        self.assertIn("tools/sourcecraft-native-qualification/tests/test_controller.py", structural)

    def test_protected_arm64_job_invokes_only_installed_authority(self) -> None:
        workflow = (ROOT / ".sourcecraft/ci.yaml").read_text()
        policy = (PACKAGE / "policy.py").read_text()
        manifest = (PACKAGE / "installation_manifest.py").read_text()
        start = workflow.index("- name: qualification-native-macos")
        section = workflow[start:workflow.index("- name: qualification-native-macos-x86_64", start)]
        signer = "/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-sign-evidence"
        request = "/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-request-signature"
        for command in ("test -x /opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-controller", "test -x /opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-verifier", f"test -x {request}", "test -S /private/var/run/gocode/sourcecraft-native-qualification-sign.sock", "test -r /private/etc/gocode/sourcecraft-native-qualification/policy.json", "/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-controller", request, "/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-verifier"):
            self.assertIn(command, section)
        self.assertIn("EVIDENCE_SIGNER", policy)
        self.assertIn('"signer.py"', manifest)
        self.assertIn('"sourcecraft-native-qualification-sign-evidence"', manifest)
        self.assertIn('"signer_broker.py"', manifest)
        self.assertNotIn(f"- {signer}\n", section)
        controller = "- /opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-controller"
        self.assertLess(section.index(controller), section.index(f"- {request}"))
        self.assertLess(section.index(f"- {request}"), section.index("- /opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-verifier"))


if __name__ == "__main__": unittest.main()
