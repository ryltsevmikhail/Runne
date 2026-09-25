from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.security.tests.test_validate_credential_secret_surfaces import (
    GUARDED_PATHS,
    REPO,
    VALIDATOR,
)


class CredentialSecretBundleTests(unittest.TestCase):
    def test_malformed_digest_entry_is_reported_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in GUARDED_PATHS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / relative, target)
            bundle_path = root / "contracts/gocode-ui-client-2/bundle.json"
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            bundle["artifactDigests"].append(None)
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(VALIDATOR), "--root", str(root)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("SURFACE_PUBLIC_CONTRACT_V1", result.stdout)
        self.assertIn("artifactDigests must be an array of objects", result.stdout)
        self.assertNotIn("Traceback", result.stderr)
