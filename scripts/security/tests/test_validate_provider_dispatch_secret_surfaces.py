from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.security.tests.test_validate_credential_secret_surfaces import (
    GUARDED_PATHS as BASE_GUARDED_PATHS,
)


REPO = Path(__file__).resolve().parents[3]
VALIDATOR = REPO / "scripts/security/validate_credential_secret_surfaces.py"
GUARDED_PATHS = BASE_GUARDED_PATHS + (
    "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos.rs",
    "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/routes.rs",
    "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/cleanup.rs",
    "crates/runne-secure-store/src/provider_credential/policy.rs",
    "crates/runne-daemon/src/protected_activation/credential_service_gateway.rs",
    "crates/runne-daemon-openai-effect/src/client.rs",
    "crates/runne-daemon-openai-effect/src/bounds.rs",
    "crates/runne-daemon-deepseek-effect/src/client.rs",
    "crates/runne-daemon-deepseek-effect/src/bounds.rs",
)


class ProviderDispatchSecretSurfaceValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp: tempfile.TemporaryDirectory[str] | None = None
        self.reset_fixture()

    def reset_fixture(self) -> None:
        if self.temp is not None:
            self.temp.cleanup()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for relative in GUARDED_PATHS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / relative, destination)

    def tearDown(self) -> None:
        if self.temp is not None:
            self.temp.cleanup()
            self.temp = None

    def mutate(self, path: str, before: str, after: str) -> None:
        target = self.root / path
        source = target.read_text(encoding="utf-8")
        self.assertIn(before, source)
        target.write_text(source.replace(before, after, 1), encoding="utf-8")

    def assert_rejected(self, code: str) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), "--root", str(self.root)],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(code, result.stdout)

    def test_gateway_and_provider_materializers_must_transfer_ownership(self) -> None:
        mutations = (
            (
                "crates/runne-daemon/src/protected_activation/credential_service_gateway.rs",
                "ProviderCredentialMaterial::from_zeroizing(material.into_zeroizing())",
                "ProviderCredentialMaterial::new(bytes.to_vec())",
            ),
            (
                "crates/runne-daemon-openai-effect/src/client.rs",
                ".map(ProviderCredentialMaterial::into_zeroizing)",
                ".map(|value| value.with_bytes(|bytes| Zeroizing::new(bytes.to_vec())))",
            ),
            (
                "crates/runne-daemon-deepseek-effect/src/client.rs",
                ".map(ProviderCredentialMaterial::into_zeroizing)",
                ".map(|value| value.with_bytes(|bytes| Zeroizing::new(bytes.to_vec())))",
            ),
        )
        for path, before, after in mutations:
            with self.subTest(path=path):
                self.reset_fixture()
                self.mutate(path, before, after)
                self.assert_rejected("PROVIDER_DISPATCH_ZEROIZING_TRANSFER")

    def test_authorization_owner_and_sensitive_header_are_guarded(self) -> None:
        for path in (
            "crates/runne-daemon-openai-effect/src/bounds.rs",
            "crates/runne-daemon-deepseek-effect/src/bounds.rs",
        ):
            with self.subTest(path=path):
                self.reset_fixture()
                self.mutate(path, "header.set_sensitive(true);", "let _ = &header;")
                self.assert_rejected("PROVIDER_AUTHORIZATION_OWNER")

    def test_authorization_owner_additive_debug_is_rejected(self) -> None:
        for path in (
            "crates/runne-daemon-openai-effect/src/bounds.rs",
            "crates/runne-daemon-deepseek-effect/src/bounds.rs",
        ):
            with self.subTest(path=path):
                self.reset_fixture()
                self.mutate(
                    path,
                    "struct AuthorizationOwner {",
                    "#[derive(Debug)]\nstruct AuthorizationOwner {",
                )
                self.assert_rejected("PROVIDER_AUTHORIZATION_OWNER")

    def test_provider_materializer_additive_plaintext_copy_is_rejected(self) -> None:
        for path in (
            "crates/runne-daemon-openai-effect/src/client.rs",
            "crates/runne-daemon-deepseek-effect/src/client.rs",
        ):
            with self.subTest(path=path):
                self.reset_fixture()
                self.mutate(
                    path,
                    ".map(ProviderCredentialMaterial::into_zeroizing)",
                    ".map(ProviderCredentialMaterial::into_zeroizing)\n"
                    "                    .map(|bytes| { let _copy = bytes.to_vec(); bytes })",
                )
                self.assert_rejected("PROVIDER_DISPATCH_ZEROIZING_TRANSFER")

    def test_provider_material_debug_surface_is_rejected(self) -> None:
        path = "crates/runne-secure-store/src/provider_credential/policy.rs"
        self.mutate(
            path,
            "impl ProviderCredentialMaterial {",
            "impl std::fmt::Debug for ProviderCredentialMaterial {\n"
            "    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { todo!() }\n"
            "}\nimpl ProviderCredentialMaterial {",
        )
        self.assert_rejected("SECRET_TYPE_TRAITS")


if __name__ == "__main__":
    unittest.main()
