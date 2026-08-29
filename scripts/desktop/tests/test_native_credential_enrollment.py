"""Fail-closed tests for macOS credential enrollment evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.native_credential_enrollment import linux, macos, windows
from scripts.desktop.native_credential_enrollment_probe import validate_evidence


def digest(seed: str) -> str:
    return hashlib.sha256(seed.encode("ascii")).hexdigest()


def row(architecture: str, run: str) -> dict[str, object]:
    tuple_values = {
        "desktop_sha256": digest(f"desktop-{architecture}"),
        "writer_sha256": digest(f"writer-{architecture}"),
        "daemon_sha256": digest(f"daemon-{architecture}"),
        "contract_sha256": digest("contract"),
        "candidate_sha256": digest(f"candidate-{architecture}"),
    }
    selectors = {
        name: {"status": "verified"}
        for name in macos.REQUIRED_SELECTORS - {"remote_verify_after_local"}
    }
    selectors["local_verify_no_network"] = {"status": "verified", "network_attempts": 0}
    selectors["remote_verify_after_local"] = {
        "status": "unsupported",
        "local_verification": "verified",
        "retry_count": 0,
    }
    return {
        "platform": "macos",
        "architecture": architecture,
        "disposition": "verified",
        "tuple": {**tuple_values, "tuple_sha256": macos.tuple_digest(tuple_values)},
        "signing": {
            "profile": "developer_id",
            "notarized": True,
            "ad_hoc": False,
            "team_id": "EXAMPLETEAM",
        },
        "runner": {"workflow_run_id": run, "attestation_verified": True},
        "selectors": selectors,
    }


def evidence() -> dict[str, object]:
    return {
        "schema_version": "native-credential-enrollment-evidence.v1",
        "platform": "macos",
        "rows": [row("arm64", "run-arm64")],
    }


def expected_tuples() -> dict[str, object]:
    return {
        row_value["architecture"]: copy.deepcopy(row_value["tuple"])
        for row_value in evidence()["rows"]
    }


def _replace_tuple_digest(value: object, candidate: str) -> None:
    if not isinstance(value, dict):
        raise TypeError("test tuple must be an object")
    value["candidate_sha256"] = digest(candidate)
    value["tuple_sha256"] = macos.tuple_digest(value)


def linux_row(package_format: str, run: str) -> dict[str, object]:
    tuple_values = {
        "desktop_sha256": digest(f"desktop-{package_format}"),
        "writer_sha256": digest(f"writer-{package_format}"),
        "daemon_sha256": digest(f"daemon-{package_format}"),
        "contract_sha256": digest("contract"),
        "candidate_sha256": digest(f"candidate-{package_format}"),
    }
    selectors = {name: {"status": "verified"} for name in linux.REQUIRED_SELECTORS}
    selectors["local_verify_no_network"] = {"status": "verified", "network_attempts": 0}
    selectors["remote_verify_after_local"] = {
        "status": "unsupported",
        "local_verification": "verified",
        "retry_count": 0,
    }
    return {
        "platform": "linux",
        "distribution": "ubuntu-22.04",
        "architecture": "x86_64",
        "package_format": package_format,
        "disposition": "verified",
        "isolation_class": "owner_session_scoped",
        "tuple": {**tuple_values, "tuple_sha256": linux.tuple_digest(tuple_values)},
        "native_store": {"session_dbus": "verified", "keyring": "verified"},
        "runner": {"workflow_run_id": run, "attestation_verified": True},
        "selectors": selectors,
    }


def linux_evidence() -> dict[str, object]:
    return {
        "schema_version": "native-credential-enrollment-evidence.v1",
        "platform": "linux",
        "rows": [linux_row("appimage", "run-appimage"), linux_row("deb", "run-deb")],
    }


def windows_evidence() -> dict[str, object]:
    tuple_values = {
        "desktop_sha256": digest("desktop-windows"),
        "writer_sha256": digest("writer-windows"),
        "daemon_sha256": digest("daemon-windows"),
        "contract_sha256": digest("contract"),
        "candidate_sha256": digest("candidate-windows"),
    }
    selectors = {name: {"status": "verified"} for name in windows.REQUIRED_SELECTORS}
    selectors["local_verify_no_network"] = {"status": "verified", "network_attempts": 0}
    selectors["remote_verify_after_local"] = {
        "status": "unsupported",
        "local_verification": "verified",
        "retry_count": 0,
    }
    return {
        "schema_version": "native-credential-enrollment-evidence.v1",
        "platform": "windows",
        "rows": [{
            "platform": "windows",
            "version": "10-22H2",
            "architecture": "x86_64",
            "package_format": "nsis",
            "disposition": "verified",
            "isolation_class": "owner_session_scoped",
            "tuple": {**tuple_values, "tuple_sha256": windows.tuple_digest(tuple_values)},
            "native_store": {"credential_manager": "verified", "logon_session": "verified"},
            "runner": {"workflow_run_id": "run-windows", "attestation_verified": True},
            "selectors": selectors,
        }],
    }


class NativeCredentialEnrollmentEvidenceTests(unittest.TestCase):
    def test_linux_package_formats_require_owner_session_evidence(self) -> None:
        self.assertEqual(validate_evidence(linux_evidence(), "linux"), [])
        for name, mutate in (
            ("mock_keyring", lambda value: value["rows"][0]["native_store"].update(keyring="mock")),
            ("missing_dbus", lambda value: value["rows"][0]["native_store"].pop("session_dbus")),
            ("executable_acl", lambda value: value["rows"][0].update(isolation_class="executable_acl")),
            ("same_format", lambda value: value["rows"][1].update(package_format="appimage")),
            ("missing_broker", lambda value: value["rows"][0]["selectors"].pop("third_process_broker_denied")),
        ):
            with self.subTest(name=name):
                value = copy.deepcopy(linux_evidence())
                mutate(value)
                self.assertTrue(validate_evidence(value, "linux"))

    def test_windows_credential_manager_requires_logon_session_and_handle_proof(self) -> None:
        self.assertEqual(validate_evidence(windows_evidence(), "windows"), [])
        for name, mutate in (
            ("path_only", lambda value: value["rows"][0]["selectors"].pop("retained_handle_pid_reuse_denied")),
            ("wrong_isolation", lambda value: value["rows"][0].update(isolation_class="executable_acl")),
            ("missing_logon_session", lambda value: value["rows"][0]["native_store"].pop("logon_session")),
            ("compile_only", lambda value: value["rows"][0]["runner"].update(attestation_verified=False)),
        ):
            with self.subTest(name=name):
                value = copy.deepcopy(windows_evidence())
                mutate(value)
                self.assertTrue(validate_evidence(value, "windows"))

    def test_checked_in_profile_stays_unsupported_without_external_evidence(self) -> None:
        root = Path(__file__).resolve().parents[3]
        schema = json.loads(
            (root / "docs/schemas/native-credential-enrollment-evidence-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        profile = json.loads(
            (root / "docs/profiles/native-credential-enrollment-v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(schema["$id"], "gocode://schemas/native-credential-enrollment-evidence-v1")
        self.assertEqual(schema["properties"]["platform"]["enum"], ["macos", "linux", "windows"])
        self.assertIn("linux_row", schema["$defs"])
        self.assertIn("windows_row", schema["$defs"])
        self.assertEqual(schema["allOf"][0]["then"]["properties"]["rows"]["maxItems"], 1)
        self.assertEqual(schema["$defs"]["macos_row"]["properties"]["architecture"], {"const": "arm64"})
        self.assertEqual(profile["disposition"], "unsupported")
        self.assertEqual(profile["evidence_rows"], [])

    def test_complete_apple_silicon_macos_evidence_is_structurally_valid(self) -> None:
        self.assertTrue(validate_evidence(evidence(), "macos"))
        self.assertEqual(validate_evidence(evidence(), "macos", expected_tuples()), [])

    def test_unsigned_ad_hoc_non_arm64_mixed_tuple_and_missing_selector_fail_closed(self) -> None:
        cases = {
            "unsigned": lambda value: value["rows"][0]["signing"].update(notarized=False),
            "ad_hoc": lambda value: value["rows"][0]["signing"].update(ad_hoc=True),
            "intel": lambda value: value["rows"][0].update(architecture="x86_64"),
            "wrong_arch": lambda value: value["rows"][0].update(architecture="amd64"),
            "universal": lambda value: value["rows"][0].update(architecture="universal"),
            "mixed_tuple": lambda value: value["rows"][0]["tuple"].update(daemon_sha256=digest("other")),
            "missing_selector": lambda value: value["rows"][0]["selectors"].pop("pid_reuse_denied"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                value = copy.deepcopy(evidence())
                mutate(value)
                self.assertTrue(validate_evidence(value, "macos", expected_tuples()))

    def test_lifecycle_and_network_selector_invariants_fail_closed(self) -> None:
        for selector, change in (
            ("local_verify_no_network", {"status": "verified", "network_attempts": 1}),
            ("remote_verify_after_local", {"status": "verified", "local_verification": "missing", "retry_count": 0}),
            ("remote_verify_after_local", {"status": "verified", "local_verification": "verified", "retry_count": 1}),
        ):
            with self.subTest(selector=selector, change=change):
                value = evidence()
                value["rows"][0]["selectors"][selector] = change
                self.assertTrue(validate_evidence(value, "macos", expected_tuples()))

    def test_only_remote_verification_may_be_unsupported(self) -> None:
        for selector in macos.REQUIRED_SELECTORS - {"remote_verify_after_local"}:
            with self.subTest(selector=selector):
                value = evidence()
                value["rows"][0]["selectors"][selector] = {"status": "unsupported"}
                self.assertTrue(validate_evidence(value, "macos", expected_tuples()))

    def test_expected_macos_tuples_must_be_exact_and_complete(self) -> None:
        self.assertEqual(validate_evidence(evidence(), "macos", expected_tuples()), [])
        cases = {
            "missing_component": lambda rows, expected: expected["arm64"].pop("writer_sha256"),
            "changed_digest": lambda rows, expected: expected["arm64"].update(candidate_sha256=digest("other")),
            "recomputed_mixed_tuple": lambda rows, expected: _replace_tuple_digest(expected["arm64"], "other"),
            "row_tuple_mismatch": lambda rows, expected: _replace_tuple_digest(rows[0]["tuple"], "other"),
            "extra_architecture": lambda rows, expected: expected.update(x86_64=expected["arm64"]),
            "malformed_expected": lambda rows, expected: expected.clear() or expected.update(arm64=[]),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                value, expected = evidence(), expected_tuples()
                mutate(value["rows"], expected)
                self.assertTrue(validate_evidence(value, "macos", expected))

    def test_cli_requires_expected_tuples_and_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for value in evidence()["rows"]:
                root.joinpath(f"macos-13-{value['architecture']}.json").write_text(
                    json.dumps(value), encoding="utf-8"
                )
            expected = root / "expected-tuples.json"
            expected.write_text(json.dumps(expected_tuples()), encoding="utf-8")
            command = [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "native_credential_enrollment_probe.py"),
                "validate", "--platform", "macos", "--evidence-root", str(root),
            ]
            result = subprocess.run(command, capture_output=True, check=False, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            result = subprocess.run(
                [*command, "--expected-tuples", str(expected)],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)["qualified"])
            expected.write_text('{"arm64":{},"arm64":{}}', encoding="utf-8")
            result = subprocess.run(
                [*command, "--expected-tuples", str(expected)],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 1, result.stderr)

    def test_duplicate_runner_and_secret_like_field_fail_closed(self) -> None:
        value = evidence()
        value["rows"].append(row("arm64", "run-arm64"))
        value["rows"][0]["selectors"]["pair_create_readback"]["nativeHandle"] = "forbidden"
        self.assertTrue(validate_evidence(value, "macos", expected_tuples()))
        value = evidence()
        value["rows"][0]["signing"]["unexpected"] = True
        self.assertTrue(validate_evidence(value, "macos", expected_tuples()))

    def test_evidence_directory_requires_exact_apple_silicon_row(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "macos-13-arm64.json").write_text(json.dumps(evidence()["rows"][0]), encoding="utf-8")
            self.assertEqual(validate_evidence(root, "macos", expected_tuples()), [])
            (root / "macos-13-x86_64.json").write_text(json.dumps(row("x86_64", "run-x86")), encoding="utf-8")
            self.assertTrue(validate_evidence(root, "macos", expected_tuples()))
