"""Evidence counters must be integers, not bool/float values equal to integers."""
import unittest

from scripts.desktop.native_credential_enrollment import macos
from scripts.desktop.tests.test_native_credential_xpc_qualification import _row


class NativeCounterTypesTests(unittest.TestCase):
    def test_non_integer_counters_are_rejected(self):
        paths = (
            ("artifact_scan", "files_scanned"),
            ("artifact_scan", "sensitive_value_matches"),
            ("selectors", "local_verify_no_network", "network_attempts"),
            ("selectors", "remote_verify_after_local", "retry_count"),
        )
        self.assertEqual(macos.validate_row(_row()), [])
        for path in paths:
            for invalid in (True, False, 0.0, 1.0, "0", None):
                with self.subTest(path=path, invalid=invalid):
                    row = _row()
                    target = row
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = invalid
                    self.assertTrue(macos.validate_row(row))
