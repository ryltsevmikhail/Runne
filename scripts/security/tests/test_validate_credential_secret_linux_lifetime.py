from __future__ import annotations

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


LINUX_PATHS = (
    "crates/runne-platform-desktop/src/provider_credential_prompt/linux_gui.rs",
    "crates/runne-platform-desktop/src/provider_credential_prompt/linux_gui_response.rs",
    "crates/runne-secure-store/src/keyring/linux_secret_service/cache.rs",
    "crates/runne-secure-store/src/keyring/linux_secret_service/dh_session.rs",
    "crates/runne-secure-store/src/provider_credential/codec_layout.rs",
    "scripts/security/credential_secret_linux_rules.py",
)


class LinuxCredentialSecretLifetimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reset_fixture()

    def reset_fixture(self) -> None:
        if getattr(self, "temp", None) is not None:
            self.temp.cleanup()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for relative in (*GUARDED_PATHS, *LINUX_PATHS):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / relative, destination)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def mutate(self, path: str, before: str, after: str) -> None:
        target = self.root / path
        source = target.read_text(encoding="utf-8")
        self.assertIn(before, source, f"fixture anchor missing in {path}")
        target.write_text(source.replace(before, after, 1), encoding="utf-8")

    def run_validator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--root", str(self.root)],
            capture_output=True,
            check=False,
            text=True,
        )

    def assert_rejected(self, code: str) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(code, result.stdout)

    def test_linux_source_tree_is_accepted(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("credential secret surfaces: PASS", result.stdout)

    def test_missing_linux_source_is_a_guard_input_failure(self) -> None:
        (self.root / LINUX_PATHS[1]).unlink()
        self.assert_rejected("GUARD_INPUT")

    def test_prompt_response_cannot_grow_or_use_ordinary_scratch(self) -> None:
        path = LINUX_PATHS[1]
        self.mutate(
            path,
            "let mut response = Zeroizing::new(Vec::with_capacity(maximum));",
            "let mut response = Vec::new();",
        )
        self.assert_rejected("LINUX_PROMPT_RESPONSE_OWNER")

    def test_prompt_read_chunk_cannot_be_plain_stack_scratch(self) -> None:
        self.mutate(
            LINUX_PATHS[1],
            "let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_BYTES]);",
            "let mut chunk = [0_u8; READ_CHUNK_BYTES];",
        )
        self.assert_rejected("LINUX_PROMPT_RESPONSE_OWNER")

    def test_prompt_reader_keeps_deadline_poll_and_join(self) -> None:
        self.mutate(
            LINUX_PATHS[0],
            "            let _ = reader_thread.join();",
            "            drop(reader_thread);",
        )
        self.assert_rejected("LINUX_PROMPT_READER_TERMINAL")

    def test_secret_service_crypto_cannot_return_to_plain_vec_cipher_helpers(self) -> None:
        path = LINUX_PATHS[3]
        self.mutate(
            path,
            "let mut plaintext = Zeroizing::new(data.to_vec());",
            "let mut plaintext = data.to_vec();",
        )
        self.assert_rejected("LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO")
        self.reset_fixture()
        self.mutate(
            path,
            "decrypt_padded_mut::<Pkcs7>(buffer)",
            "decrypt_padded_vec_mut::<Pkcs7>(buffer)",
        )
        self.assert_rejected("LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO")

    def test_ciphertext_limit_precedes_zeroizing_copy(self) -> None:
        self.mutate(
            LINUX_PATHS[3],
            "        || data.len() > MAX_CIPHERTEXT_BYTES\n",
            "",
        )
        self.assert_rejected("LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO")

    def test_dh_key_derivation_material_cannot_be_ordinary(self) -> None:
        self.mutate(
            LINUX_PATHS[3],
            "let shared_bytes = Zeroizing::new(shared.to_bytes_be());",
            "let shared_bytes = shared.to_bytes_be();",
        )
        self.assert_rejected("LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO")

    def test_ciphertext_limit_remains_derived_from_shared_storage_ceiling(self) -> None:
        self.mutate(
            LINUX_PATHS[4],
            "+ MAX_NATIVE_OAUTH_CREDENTIAL_BYTES;",
            "+ usize::MAX;",
        )
        self.assert_rejected("LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO")

    def test_keyutils_payload_is_wrapped_at_read_boundary(self) -> None:
        self.mutate(
            LINUX_PATHS[2],
            "let buffer = Zeroizing::new(key.read_to_vec().map_err(|_| CacheError::Unavailable)?);",
            "let buffer = key.read_to_vec().map_err(|_| CacheError::Unavailable)?;",
        )
        self.assert_rejected("LINUX_KEYUTILS_ZEROIZING_READ")


if __name__ == "__main__":
    unittest.main()
