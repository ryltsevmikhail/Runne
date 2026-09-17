"""JSON Schema executes against synthetic receipts; it cannot verify signatures."""
import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.desktop.native_credential_enrollment import macos
from scripts.desktop.tests.test_native_credential_xpc_qualification import _evidence, _row, _expected
from scripts.desktop.tests.test_native_credential_xpc_preflight import envelope, context, NOW
from scripts.desktop.native_credential_enrollment.macos_preflight import validate_envelope
from scripts.desktop.native_credential_enrollment.macos_preflight import PROTECTED_SUBJECT_DIGEST_FIELDS

ROOT = Path(__file__).resolve().parents[3]


class XpcSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schemas = [json.loads((ROOT / "docs/schemas" / name).read_text()) for name in (
            "native-credential-enrollment-evidence-v1.schema.json",
            "macos-xpc-service-signed-envelope-v1.schema.json",
        )]
        for schema in schemas:
            Draft202012Validator.check_schema(schema)
        cls.evidence, cls.envelope = map(Draft202012Validator, schemas)

    def test_valid_synthetic_row_and_envelope(self):
        self.evidence.validate(_evidence())
        self.envelope.validate(envelope())

    def test_external_golden_row_and_envelope_match_schema(self):
        golden = json.loads((ROOT / "docs/golden/macos-xpc-service-external-contract-v1.json").read_text())
        files = golden["files"]
        self.evidence.validate({
            "schema_version": "native-credential-enrollment-evidence.v1",
            "platform": "macos",
            "rows": [files["macos-13-arm64.json"]],
        })
        self.envelope.validate(files["signed-envelope.json"])

    def test_envelope_schema_and_python_reject_noncanonical_signature_and_newlines(self):
        values = []
        value = envelope()
        value["signature"]["value"] = "A" * 85 + "B=="
        values.append(value)
        for key in ("source_revision", "workflow_run_id", "namespace_sha256", "signer_key_id",
                    "row_sha256", "expected_tuples_sha256", *PROTECTED_SUBJECT_DIGEST_FIELDS,
                    "started_at", "finished_at"):
            value = envelope()
            value[key] += "\n"
            values.append(value)
        value = envelope()
        value["signature"]["value"] += "\n"
        values.append(value)
        for value in values:
            with self.subTest(value=value):
                self.assertTrue(validate_envelope(value, _row(), _expected(), context(), NOW))
                self.assertFalse(self.envelope.is_valid(value))

    def test_row_schema_and_python_reject_identifier_digest_and_version_newlines(self):
        for path in (("os_version",), ("runner", "workflow_run_id"), ("tuple", "desktop_sha256")):
            value = _evidence()
            target = value["rows"][0]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] += "\n"
            self.assertTrue(macos.validate_row(value["rows"][0]))
            self.assertFalse(self.evidence.is_valid(value))

    def test_missing_row_fields_and_each_skipped_selector_rejected(self):
        for field in _evidence()["rows"][0]:
            value = _evidence()
            del value["rows"][0][field]
            self.assertFalse(self.evidence.is_valid(value), field)
        for selector in macos.REQUIRED_SELECTORS - {"remote_verify_after_local"}:
            for status in ("unsupported", "skipped", "allowed"):
                value = _evidence()
                value["rows"][0]["selectors"][selector]["status"] = status
                self.assertFalse(self.evidence.is_valid(value), selector)

    def test_schema_rejects_cross_variant_receipts_and_misbound_nested_identity(self):
        cases = {
            "ordinary_network": lambda row: row["selectors"]["clean_install"].update(network_attempts=0),
            "local_remote": lambda row: row["selectors"]["local_verify_no_network"].update(
                local_verification="verified", retry_count=0
            ),
            "remote_network": lambda row: row["selectors"]["remote_verify_after_local"].update(network_attempts=0),
            "code_identity_role": lambda row: row["code_identities"]["desktop"].update(role="writer"),
            "code_identity_identifier": lambda row: row["code_identities"]["desktop"].update(identifier="runned"),
            "code_identity_team": lambda row: row["code_identities"]["desktop"].update(teamIdentifier="AAAAAAAAAA"),
            "code_identity_cdhash": lambda row: row["code_identities"]["desktop"].update(cdhash="a" * 39),
            "code_identity_cdhash_upper": lambda row: row["code_identities"]["desktop"].update(cdhash="A" * 40),
            "code_identity_cdhash_newline": lambda row: row["code_identities"]["desktop"].update(cdhash="a" * 40 + "\n"),
            "code_identity_requirement": lambda row: row["code_identities"]["desktop"].update(requirement="anchor apple generic"),
            "nested_selector": lambda row: row["selectors"]["clean_install"]["case_receipt"].update(selector="rotation"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                value = _evidence()
                mutate(value["rows"][0])
                self.assertTrue(macos.validate_row(value["rows"][0]))
                self.assertFalse(self.evidence.is_valid(value))

    def test_each_tuple_field_and_deployment_metadata_required(self):
        for field in _evidence()["rows"][0]["tuple"]:
            value = _evidence()
            del value["rows"][0]["tuple"][field]
            self.assertFalse(self.evidence.is_valid(value), field)
        value = _evidence()
        value["rows"][0]["deployment"]["entitlements"]["writer"] = {
            "keychain-access-groups": ["758F9Z45SR.com.runne.credential-service"],
        }
        self.assertFalse(self.evidence.is_valid(value))

    def test_envelope_unknown_missing_and_invalid_signature_fields(self):
        for field in envelope():
            value = copy.deepcopy(envelope())
            del value[field]
            self.assertFalse(self.envelope.is_valid(value), field)
        value = envelope()
        value["secret"] = "canary"
        self.assertFalse(self.envelope.is_valid(value))
        value = envelope()
        value["signature"]["value"] = "unsigned"
        self.assertFalse(self.envelope.is_valid(value))


if __name__ == "__main__":
    unittest.main()
