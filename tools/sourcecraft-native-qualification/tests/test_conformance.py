from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[1]
sys.path.insert(0, str(PACKAGE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from codec import Rejected, canonical, digest
from contract import ROLE_PATHS
from ed25519_verify import _L, verify
from vector_harness import evaluate
from conformance_support import (
    _bind_lifecycle_package,
    _hash,
    _negative_row_workflow,
    _negative_selector_fact,
    _resign,
    _vector,
)

class ConformanceTests(unittest.TestCase):
    def test_rfc8032_vectors_and_negative_forms(self) -> None:
        cases = (("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c","72","92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"))
        for public, message, signature in cases:
            with self.subTest(message=message):
                self.assertTrue(verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)))
                self.assertFalse(verify(bytes.fromhex(public), bytes.fromhex(message + "00"), bytes.fromhex(signature)))
                self.assertFalse(verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature[:-4] + "0100")))
                self.assertFalse(verify(b"\0" * 32, bytes.fromhex(message), bytes.fromhex(signature)))
                self.assertFalse(verify(bytes.fromhex(public), b"runne/macos-xpc-service-qualification/v2", bytes.fromhex(signature)))
                scalar = int.from_bytes(bytes.fromhex(signature)[32:], "little") + _L
                self.assertFalse(verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)[:32] + scalar.to_bytes(32, "little", signed=False)[-32:]))

    def test_test_harness_accepts_full_signed_vector(self) -> None:
        self.assertTrue(evaluate(_vector())["qualified"])

    def test_checked_in_positive_and_negative_corpus(self) -> None:
        import subprocess
        vectors = PACKAGE / "vectors"
        positives = (ROOT / "docs/golden/macos-xpc-service-external-contract-v1.json", vectors / "accepted-writer-v2.json")
        command = [sys.executable, str(PACKAGE / "vector_harness.py"), "--vector"]
        for positive in positives:
            self.assertEqual(subprocess.run(command + [str(positive)], capture_output=True, text=True, check=False).returncode, 0)
        negatives = {
            "negative-row-workflow-v2.json":"row workflow identity",
            "negative-selector-fact-v2.json":"selector semantic receipt",
        }
        for name, reason in negatives.items():
            vector = json.loads((vectors / name).read_text())
            with self.assertRaisesRegex(Rejected, reason): evaluate(vector)
            self.assertEqual(subprocess.run(command + [str(vectors / name)], capture_output=True, text=True, check=False).returncode, 1)

    def test_adversarial_rows_and_receipts_are_rejected(self) -> None:
        cases = {"missing_selector":lambda value:value["files"]["macos-13-arm64.json"]["selectors"].pop("rotation"),"ordinary_writer":lambda value:value["files"]["writer-transcript-v2.json"].update(attestation=1),"missing_service_admission":lambda value:value["files"].pop("service-admission.json"),"extra_inventory":lambda value:value["files"].update(extra={}),"manifest_tamper":lambda value:value["files"]["artifact-manifest.json"]["files"][0].update(sha256="0" * 64),"candidate_tuple":lambda value:value["files"]["expected-tuples.json"]["arm64"].update(candidate_sha256="0" * 64),"test_attestation_replaced":lambda value:value.update(attestation={})}
        for name, mutate in cases.items():
            with self.subTest(name=name):
                value = _vector(); mutate(value)
                with self.assertRaises(Rejected): evaluate(value)

    def test_validly_resigned_non_macho_role_is_rejected(self) -> None:
        value = _vector(); package = value["package"]; files = value["files"]
        assert isinstance(package, dict) and isinstance(files, dict)
        role = ROLE_PATHS["desktop"]; package[role] = {"base64":base64.b64encode(b"NOT-MACHO exported-canary").decode()}
        files["artifact-manifest.json"]["role_measurements"]["desktop"] = {"sha256":hashlib.sha256(b"NOT-MACHO exported-canary").hexdigest(),"size":25,"macho_magic":"4e4f542d","architecture":"unsupported","canary_matches":0}
        _bind_lifecycle_package(value)
        _resign(value, refresh_inventory=False)
        with self.assertRaises(Rejected): evaluate(value)

    def test_validly_resigned_macho_canary_export_is_rejected(self) -> None:
        value = _vector(); package = value["package"]; files = value["files"]
        assert isinstance(package, dict) and isinstance(files, dict)
        role = ROLE_PATHS["writer"]; payload = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01runne/native-qualification-export-canary/v1"
        package[role] = {"base64":base64.b64encode(payload).decode()}
        files["artifact-manifest.json"]["role_measurements"]["writer"] = {"sha256":hashlib.sha256(payload).hexdigest(),"size":len(payload),"macho_magic":"cffaedfe","architecture":"arm64","canary_matches":1}
        _bind_lifecycle_package(value)
        _resign(value)
        with self.assertRaises(Rejected): evaluate(value)

    def test_validly_resigned_lifecycle_reordering_is_rejected(self) -> None:
        value = _vector(); files = value["files"]; assert isinstance(files, dict)
        files["controller-lifecycle.json"]["order"] = ["preflight","request","execute"]
        _resign(value)
        with self.assertRaises(Rejected): evaluate(value)

    def test_validly_resigned_lifecycle_package_subject_mismatch_is_rejected(self) -> None:
        value = _vector(); files = value["files"]; assert isinstance(files, dict)
        files["controller-lifecycle.json"]["package_subject_sha256"] = "0" * 64
        _resign(value)
        with self.assertRaises(Rejected): evaluate(value)

    def test_validly_resigned_lifecycle_receipt_hashes_are_recomputed(self) -> None:
        for field in ("request_sha256", "attestation_receipt_sha256", "preflight_sha256", "result_sha256"):
            with self.subTest(field=field):
                value = _vector(); value["files"]["controller-lifecycle.json"][field] = "0" * 64
                _resign(value)
                with self.assertRaisesRegex(Rejected, "controller lifecycle receipts differ"): evaluate(value)

    def test_validly_resigned_duplicate_package_inventory_is_rejected(self) -> None:
        value = _vector(); manifest = value["files"]["artifact-manifest.json"]
        assert isinstance(manifest, dict)
        manifest["package_files"].append(copy.deepcopy(manifest["package_files"][0]))
        _resign(value, refresh_inventory=False)
        with self.assertRaisesRegex(Rejected, "package inventory is invalid"): evaluate(value)

    def test_checked_in_negative_semantics_reach_target_validation(self) -> None:
        with self.assertRaisesRegex(Rejected, "row workflow identity"):
            evaluate(_negative_row_workflow())
        with self.assertRaisesRegex(Rejected, "selector semantic receipt"):
            evaluate(_negative_selector_fact())



from conformance_native_tests import NativeConformanceTests


if __name__ == "__main__": unittest.main()
