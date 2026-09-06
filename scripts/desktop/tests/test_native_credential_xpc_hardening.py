"""Adversarial structural evidence tests; no native APIs or signed evidence."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.native_credential_enrollment import macos
from scripts.desktop.native_credential_enrollment_probe import _load_json, validate_evidence
from scripts.desktop.tests.test_native_credential_xpc_qualification import _evidence, _expected


class XpcEvidenceHardeningTests(unittest.TestCase):
    def test_document_cannot_hide_secret_fields_outside_row(self):
        value = _evidence()
        value["secret"] = "must-not-appear-in-diagnostics"
        errors = validate_evidence(value, "macos", _expected())
        self.assertTrue(errors)
        self.assertNotIn(value["secret"], repr(errors))

    def test_runner_and_os_version_cannot_carry_paths_or_keychain_selectors(self):
        for invalid in ("/Users/private/secret", "RUNNE_CI_MACOS_KEYCHAIN", "kSecUseKeychain"):
            with self.subTest(invalid=invalid):
                value = _evidence()
                value["rows"][0]["runner"]["workflow_run_id"] = invalid
                errors = validate_evidence(value, "macos", _expected())
                self.assertTrue(errors)
                self.assertNotIn(invalid, repr(errors))
        value = _evidence()
        value["rows"][0]["os_version"] = "14./Users/private/secret"
        self.assertTrue(validate_evidence(value, "macos", _expected()))

    def test_malformed_shapes_fail_closed_without_exception(self):
        for field, invalid in (("runner", []), ("runner", {"workflow_run_id": []}),
                               ("architecture", []), ("selectors", {"wrong_peer_denied": {"status": []}})):
            with self.subTest(field=field, invalid=invalid):
                value = _evidence()
                value["rows"][0][field] = invalid
                self.assertTrue(validate_evidence(value, "macos", _expected()))

    def test_inputs_are_bounded_and_json_numbers_are_finite(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "row.json"
            for raw in ('{"value":NaN}', '{"value":Infinity}', '"' + 'x' * 131073 + '"',
                        '[' * 1000 + '0' + ']' * 1000):
                with self.subTest(length=len(raw)):
                    path.write_text(raw)
                    with self.assertRaises(ValueError):
                        _load_json(path)

    def test_all_release_v3_bindings_are_required(self):
        required = {"release_tuple_v3_sha256", "deployment_sha256",
                    "desktop_code_identity_sha256", "writer_code_identity_sha256",
                    "daemon_code_identity_sha256", "service_code_identity_sha256"}
        self.assertTrue(required <= set(macos.TUPLE_FIELDS))
        self.assertIn("deployment", _evidence()["rows"][0])

    def test_shared_role_image_or_identity_is_invalid_even_when_expected_matches(self):
        for suffix in ("sha256", "code_identity_sha256"):
            value = _evidence()
            binding = value["rows"][0]["tuple"]
            binding[f"writer_{suffix}"] = binding[f"daemon_{suffix}"]
            binding["tuple_sha256"] = macos.tuple_digest(binding)
            self.assertTrue(validate_evidence(value, "macos", {"arm64": copy.deepcopy(binding)}))

    def test_absent_rows_and_each_kill_point_are_fail_closed(self):
        value = _evidence()
        value["rows"] = []
        self.assertTrue(validate_evidence(value, "macos", _expected()))
        for name in macos.REQUIRED_SELECTORS:
            if not name.startswith("kill_"):
                continue
            for invalid in ("skipped", "unsupported", "allowed"):
                with self.subTest(name=name, invalid=invalid):
                    value = copy.deepcopy(_evidence())
                    value["rows"][0]["selectors"][name]["status"] = invalid
                    self.assertTrue(validate_evidence(value, "macos", _expected()))


if __name__ == "__main__":
    unittest.main()
