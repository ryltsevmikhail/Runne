from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path


class LocalInputReceiptTmpdirTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "macOS system alias contract")
    def test_standard_macos_var_alias_resolves_to_private_var(self):
        runtime = importlib.import_module("scripts.ci_local_receipt_runtime")
        configured = Path(os.environ["TMPDIR"])
        self.assertTrue(os.fspath(configured).startswith("/var/"))
        self.assertEqual(runtime._private_tmpdir(configured), configured.resolve(strict=True))

    def test_arbitrary_symlink_to_private_directory_is_rejected(self):
        runtime = importlib.import_module("scripts.ci_local_receipt_runtime")
        receipt = importlib.import_module("scripts.ci_local_receipt")
        with tempfile.TemporaryDirectory() as location:
            root = Path(location)
            private = root / "private"
            private.mkdir(mode=0o700)
            alias = root / "alias"
            alias.symlink_to(private)
            with self.assertRaises(receipt.LocalInputReceiptError):
                runtime._private_tmpdir(alias)


if __name__ == "__main__":
    unittest.main()
