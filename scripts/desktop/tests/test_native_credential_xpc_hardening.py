"""Adversarial structural evidence tests; no native APIs or signed evidence."""
import copy
import json
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
            path = Path(temporary).resolve() / "row.json"
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


class EvidenceDescriptorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / "row.json"
        self.path.write_text('{"safe":true}')

    def assert_rejected(self, path):
        with self.assertRaises(ValueError) as caught:
            _load_json(path)
        self.assertNotIn(str(path), str(caught.exception))
        self.assertNotIn(self.root.name, str(caught.exception))

    def test_final_symlink_and_parent_symlink_are_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.path)
        self.assert_rejected(link)
        parent = self.root / "parent"
        parent.symlink_to(self.root, target_is_directory=True)
        self.assert_rejected(parent / self.path.name)

    def test_fifo_socket_device_and_directory_are_rejected(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.assert_rejected(fifo)
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.bind(str(self.root / "s"))
            self.assert_rejected(self.root / "s")
        self.assert_rejected(Path("/dev/null"))
        self.assert_rejected(self.root)

    def test_regular_replacement_with_symlink_or_fifo_cannot_bypass_descriptor_checks(self):
        original_open, original_path_open = os.open, Path.open
        for replacement in ("symlink", "fifo"):
            with self.subTest(replacement=replacement):
                if self.path.exists() or self.path.is_symlink():
                    self.path.unlink()
                self.path.write_text('{"safe":true}')
                target = self.root / "target"
                target.write_text('{"unsafe":true}')
                changed = False

                def replace():
                    nonlocal changed
                    if changed:
                        return
                    changed = True
                    self.path.unlink()
                    if replacement == "symlink":
                        self.path.symlink_to(target)
                    else:
                        os.mkfifo(self.path)

                def descriptor_open(name, flags, *args, **kwargs):
                    if str(name) == self.path.name:
                        replace()
                        self.assertTrue(flags & os.O_NOFOLLOW)
                        self.assertTrue(flags & os.O_NONBLOCK)
                    return original_open(name, flags, *args, **kwargs)

                def pathname_open(path, *args, **kwargs):
                    if path == self.path:
                        replace()
                        if replacement == "fifo":
                            self.fail("blocking pathname open attempted after FIFO replacement")
                    return original_path_open(path, *args, **kwargs)

                with patch("os.open", side_effect=descriptor_open), patch.object(Path, "open", pathname_open):
                    self.assert_rejected(self.path)
                self.assertTrue(changed)

    def test_opened_parent_remains_anchored_after_path_is_replaced(self):
        parent, replacement = self.root / "parent", self.root / "other"
        parent.mkdir()
        replacement.mkdir()
        path = parent / "row.json"
        path.write_text('{"safe":true}')
        (replacement / "row.json").write_text('{"unsafe":true}')
        original_open, original_path_open = os.open, Path.open
        changed = False

        def replace():
            nonlocal changed
            if not changed:
                changed = True
                parent.rename(self.root / "held")
                parent.symlink_to(replacement, target_is_directory=True)

        def descriptor_open(name, flags, *args, **kwargs):
            if str(name) == path.name:
                replace()
                self.assertIsNotNone(kwargs.get("dir_fd"))
            return original_open(name, flags, *args, **kwargs)

        def pathname_open(candidate, *args, **kwargs):
            if candidate == path:
                replace()
            return original_path_open(candidate, *args, **kwargs)

        with patch("os.open", side_effect=descriptor_open), patch.object(Path, "open", pathname_open):
            self.assertEqual(_load_json(path), {"safe": True})
        self.assertTrue(changed)

    def test_read_uses_opened_regular_descriptor_after_final_path_replacement(self):
        original_fstat = os.fstat
        for replacement in ("symlink", "fifo"):
            with self.subTest(replacement=replacement):
                if self.path.exists() or self.path.is_symlink():
                    self.path.unlink()
                self.path.write_text('{"safe":true}')
                target = self.root / "target"
                target.write_text('{"unsafe":true}')
                changed = False

                def descriptor_info(descriptor):
                    nonlocal changed
                    info = original_fstat(descriptor)
                    if stat.S_ISREG(info.st_mode) and not changed:
                        changed = True
                        self.path.unlink()
                        if replacement == "symlink":
                            self.path.symlink_to(target)
                        else:
                            os.mkfifo(self.path)
                    return info

                with patch("os.fstat", side_effect=descriptor_info):
                    self.assertEqual(_load_json(self.path), {"safe": True})
                self.assertTrue(changed)


if __name__ == "__main__":
    unittest.main()
