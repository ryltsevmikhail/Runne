"""Task 10 fail-closed tests for the signed macOS XPC qualification row."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.native_credential_enrollment import macos
from scripts.desktop.native_credential_enrollment.macos_bindings import DEPLOYMENT, canonical_digest
from scripts.desktop.native_credential_enrollment.macos_receipts import CANARY_DIGEST, ROLE_IDENTIFIERS, TEAM_ID
from scripts.desktop.native_credential_enrollment_probe import validate_evidence

ROOT = Path(__file__).resolve().parents[3]
PROTECTED_PACKAGE = ROOT / "tools" / "sourcecraft-native-qualification"
if str(PROTECTED_PACKAGE) not in sys.path:
    sys.path.insert(0, str(PROTECTED_PACKAGE))
from codec import Rejected
from contract import validate_row as validate_protected_row


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode("ascii")).hexdigest()


def _selector(name: str, run: str) -> dict[str, object]:
    status = "unsupported" if name == "remote_verify_after_local" else "verified"
    case = {"ordinal": sorted(macos.REQUIRED_SELECTORS).index(name), "selector": name, "workflow_run_id": run}
    process = {"outcome": status, "selector": name}
    terminal = {"cleanup_verified": True, "selector": name, "state": status}
    namespace = {"exact_cleanup": True, "selector": name}
    receipt = {
        "status": status, "workflow_run_id": run, "case_receipt": case,
        "process_signal": process, "terminal_state": terminal, "namespace": namespace,
        "ticket_sha256": canonical_digest(case), "process_signal_sha256": canonical_digest(process),
        "terminal_state_sha256": canonical_digest(terminal), "namespace_sha256": canonical_digest(namespace),
    }
    if name == "local_verify_no_network":
        receipt["network_attempts"] = 0
    if name == "remote_verify_after_local":
        receipt.update(local_verification="verified", retry_count=0)
    return receipt


def _row() -> dict[str, object]:
    tuple_values = {
        "desktop_sha256": _digest("desktop"),
        "writer_sha256": _digest("writer"),
        "daemon_sha256": _digest("daemon"),
        "service_sha256": _digest("service"),
        "launch_agent_plist_sha256": _digest("launch-agent"),
        "entitlements_sha256": _digest("entitlements"),
        "provisioning_sha256": _digest("provisioning"),
        "protocol_sha256": _digest("protocol"),
        "contract_sha256": _digest("contract"),
        "candidate_sha256": _digest("candidate"),
        "release_tuple_v3_sha256": _digest("release-tuple-v3"),
        "deployment_sha256": canonical_digest(DEPLOYMENT),
        "desktop_code_identity_sha256": _digest("desktop-code-identity"),
        "writer_code_identity_sha256": _digest("writer-code-identity"),
        "daemon_code_identity_sha256": _digest("daemon-code-identity"),
        "service_code_identity_sha256": _digest("service-code-identity"),
    }
    code_identities = {
        role: {
            "identifier": identifier, "teamIdentifier": TEAM_ID,
            "cdhash": _digest(f"{role}-cdhash")[:40],
        }
        for role, identifier in ROLE_IDENTIFIERS.items()
    }
    for role, receipt in code_identities.items():
        tuple_values[f"{role}_code_identity_sha256"] = canonical_digest(receipt)
    run = "isolated-macos-run-1"
    selectors = {name: _selector(name, run) for name in macos.REQUIRED_SELECTORS}
    return {
        "platform": "macos",
        "architecture": "arm64",
        "os_version": "14.6",
        "disposition": "verified",
        "deployment": copy.deepcopy(DEPLOYMENT),
        "tuple": {**tuple_values, "tuple_sha256": macos.tuple_digest(tuple_values)},
        "code_identities": code_identities,
        "signing": {
            "profile": "developer_id", "notarized": True, "ad_hoc": False,
            "team_id": "758F9Z45SR",
            "code_identifiers": {
                "desktop": "com.runne.desktop", "writer": "runne", "daemon": "runned",
                "service": "com.runne.credential-service",
            },
            "application_identifiers": {
                "desktop": "758F9Z45SR.com.runne.desktop",
                "service": "758F9Z45SR.com.runne.credential-service",
            },
        },
        "runner": {
            "workflow_run_id": run, "attestation_verified": True,
            "freshness_verified": True, "isolated_disposable_user": True,
            "icloud_data_present": False, "user_keychain_data_present": False,
        },
        "native_store": {
            "access_group": "758F9Z45SR.com.runne.credential-service",
            "data_protection_keychain": True,
            "accessibility": "when_unlocked_this_device_only",
            "synchronizable": False,
            "file_keychain": False,
            "environment_keychain": False,
            "ksec_use_keychain": False,
            "legacy_acl": False,
        },
        "artifact_scan": {
            "files_scanned": 8, "sensitive_value_matches": 0,
            "scan_subject_sha256": _digest("scan-subject"), "canary_sha256": CANARY_DIGEST,
        },
        "selectors": selectors,
    }


def _evidence() -> dict[str, object]:
    return {
        "schema_version": "native-credential-enrollment-evidence.v1",
        "platform": "macos",
        "rows": [_row()],
    }


def _expected() -> dict[str, object]:
    return {"arm64": copy.deepcopy(_row()["tuple"])}


class MacosXpcQualificationTests(unittest.TestCase):
    def test_schema_requires_signed_xpc_dpk_bindings(self) -> None:
        schema = json.loads((ROOT / "docs/schemas/native-credential-enrollment-evidence-v1.schema.json").read_text())
        definition = schema["$defs"]["macos_row"]
        self.assertEqual(set(definition["required"]), set(_row()))
        self.assertEqual(set(definition["properties"]["tuple"]["required"]), set(_row()["tuple"]))
        self.assertEqual(
            set(definition["properties"]["selectors"]["required"]),
            macos.REQUIRED_SELECTORS,
        )
        store = definition["properties"]["native_store"]["properties"]
        self.assertEqual(store["data_protection_keychain"], {"type": "boolean", "const": True})
        self.assertEqual(store["file_keychain"], {"type": "boolean", "const": False})
        self.assertEqual(store["accessibility"], {"const": "when_unlocked_this_device_only"})

    def test_exact_signed_isolated_dpk_row_is_structurally_valid(self) -> None:
        self.assertEqual(validate_evidence(_evidence(), "macos", _expected()), [])

    def test_artifact_and_identity_bindings_fail_closed(self) -> None:
        cases = {
            "missing_service": lambda row: row["tuple"].pop("service_sha256"),
            "wrong_service_id": lambda row: row["signing"]["application_identifiers"].update(
                service="758F9Z45SR.com.example.service"
            ),
            "shared_identity": lambda row: row["signing"]["code_identifiers"].update(
                writer=row["signing"]["code_identifiers"]["desktop"]
            ),
            "malformed_identities": lambda row: row["signing"].update(application_identifiers=[]),
            "stale": lambda row: row["runner"].update(freshness_verified=False),
            "unattested": lambda row: row["runner"].update(attestation_verified=False),
            "sensitive_artifact": lambda row: row["artifact_scan"].update(
                sensitive_value_matches=1
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                value = _evidence()
                mutate(value["rows"][0])
                self.assertTrue(validate_evidence(value, "macos", _expected()))

    def test_non_dpk_or_nonisolated_context_fails_closed(self) -> None:
        cases = {
            "wrong_accessibility": lambda row: row["native_store"].update(
                accessibility="after_first_unlock_this_device_only"
            ),
            "not_dpk": lambda row: row["native_store"].update(data_protection_keychain=False),
            "file_keychain": lambda row: row["native_store"].update(file_keychain=True),
            "environment_keychain": lambda row: row["native_store"].update(
                environment_keychain=True
            ),
            "ksec_selector": lambda row: row["native_store"].update(ksec_use_keychain=True),
            "shared_access_group": lambda row: row["native_store"].update(
                access_group="758F9Z45SR.com.runne.desktop"
            ),
            "sync": lambda row: row["native_store"].update(synchronizable=True),
            "real_user_data": lambda row: row["runner"].update(user_keychain_data_present=True),
            "icloud": lambda row: row["runner"].update(icloud_data_present=True),
            "not_disposable": lambda row: row["runner"].update(isolated_disposable_user=False),
            "old_macos": lambda row: row.update(os_version="12.7"),
            "malformed_macos": lambda row: row.update(os_version="latest"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                value = _evidence()
                mutate(value["rows"][0])
                self.assertTrue(validate_evidence(value, "macos", _expected()))

    def test_boolean_integer_substitutes_are_rejected_by_candidate_and_protected_contract(self) -> None:
        cases = {
            "code_identity": lambda row: row["code_identities"]["desktop"].update(cdhash=1),
            "selector_terminal": lambda row: row["selectors"]["clean_install"]["terminal_state"].update(cleanup_verified=1),
            "selector_namespace": lambda row: row["selectors"]["clean_install"]["namespace"].update(exact_cleanup=1),
            "selector_ordinal": lambda row: row["selectors"]["account_only_mismatch_denied"]["case_receipt"].update(ordinal=False),
            "deployment_keep_alive": lambda row: row["deployment"].update(keep_alive=0),
            "deployment_mach_service": lambda row: row["deployment"]["mach_services"].update(
                {"com.runne.credential-service.desktop.v1": 1}
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                row = _row()
                mutate(row)
                self.assertTrue(macos.validate_row(row))
                policy = {
                    "candidate_sha256": row["tuple"]["candidate_sha256"],
                    "release_tuple_v3_sha256": row["tuple"]["release_tuple_v3_sha256"],
                }
                with self.assertRaises(Rejected):
                    validate_protected_row(row, {"arm64": row["tuple"]}, policy)

    def test_malformed_nested_receipts_return_redacted_errors_in_public_and_cli_paths(self) -> None:
        for field, malformed in (("terminal_state", None), ("terminal_state", 1), ("namespace", [])):
            with self.subTest(field=field, malformed=repr(malformed)):
                value = _evidence()
                value["rows"][0]["selectors"]["clean_install"][field] = malformed
                self.assertTrue(validate_evidence(value, "macos", _expected()))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = _row()
            row["selectors"]["clean_install"]["terminal_state"] = None
            (root / "macos-13-arm64.json").write_text(json.dumps(row))
            tuples = root / "expected-tuples.json"
            tuples.write_text(json.dumps(_expected()))
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/desktop/native_credential_enrollment_probe.py"),
                 "validate", "--platform", "macos", "--evidence-root", str(root),
                 "--expected-tuples", str(tuples)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report["qualified"])
            self.assertFalse(report["structurally_valid"])
            self.assertTrue(report["errors"])
            self.assertNotIn("None", result.stdout + result.stderr)

    def test_native_store_rejects_numeric_boolean_substitutes(self) -> None:
        fields = {
            "data_protection_keychain": 1, "synchronizable": 0,
            "file_keychain": 0, "environment_keychain": 0,
            "ksec_use_keychain": 0, "legacy_acl": 0,
        }
        for field, number in fields.items():
            for substitute in (number, float(number)):
                with self.subTest(field=field, substitute=repr(substitute)):
                    value = _evidence()
                    value["rows"][0]["native_store"][field] = substitute
                    self.assertTrue(validate_evidence(value, "macos", _expected()))

    def test_every_peer_and_kill_point_receipt_is_required(self) -> None:
        required = {
            "standalone_writer_denied", "standalone_daemon_denied",
            "wrong_peer_denied", "kill_before_service_consume",
            "kill_after_service_consume", "kill_before_native_effect",
            "kill_after_native_effect", "kill_before_readback", "kill_after_readback",
            "kill_before_reply", "kill_after_reply", "kill_before_lifecycle_cas",
            "kill_after_lifecycle_cas", "stored_attributes_verified",
            "service_restart_persistence", "duplicate_version_denied",
            "account_only_mismatch_denied",
        }
        self.assertTrue(required <= macos.REQUIRED_SELECTORS)
        allowed = _evidence()
        allowed["rows"][0]["selectors"]["standalone_writer_denied"] = {"status": "allowed"}
        self.assertTrue(validate_evidence(allowed, "macos", _expected()))
        for selector in required:
            with self.subTest(selector=selector):
                value = _evidence()
                value["rows"][0]["selectors"].pop(selector)
                self.assertTrue(validate_evidence(value, "macos", _expected()))


if __name__ == "__main__":
    unittest.main()
