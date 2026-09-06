from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
VALIDATOR = REPO / "scripts/security/validate_credential_secret_surfaces.py"
GUARDED_PATHS = (
    "apps/desktop/src/shared/api/platform/providers.ts",
    "apps/desktop/src/pages/providers/ui/ProvidersPage.vue",
    "apps/desktop/src-tauri/src/provider_credential_enrollment/command.rs",
    "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos.rs",
    "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/routes.rs",
    "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/cleanup.rs",
    "crates/runne-app-core/src/lib_parts/providers.rs",
    "crates/runne-runtime-client/src/canonical/provider_credentials.rs",
    "crates/runne-http/src/provider_credentials.rs",
    "contracts/gocode-ui-client-2/schemas/provider-credentials-v1.schema.json",
    "contracts/gocode-ui-client-2/openapi.json",
    "crates/runne-platform-ports/src/provider_credential_prompt.rs",
    "crates/runne-provider/src/credential/enrollment/service_protocol/types.rs",
    "crates/runne-provider/src/credential/enrollment/service_protocol/codec.rs",
    "crates/runne-provider/src/credential/enrollment/service_protocol/codec/reply.rs",
    "crates/runne-provider/src/credential/enrollment/service_protocol/frame.rs",
    "crates/runne-credential-service/src/keychain/native.rs",
    "crates/runne-credential-service/src/service_backend.rs",
    "crates/runne-macos-xpc/src/frame.rs",
    "crates/runne-macos-xpc/src/client/native.rs",
    "crates/runne-macos-xpc/src/client/native/call_state.rs",
    "crates/runne-macos-xpc/src/client/native/exchange.rs",
    "crates/runne-secure-store/src/provider_credential/policy.rs",
    "crates/runne-daemon/src/protected_activation/credential_service_gateway.rs",
    "crates/runne-daemon-openai-effect/src/client.rs",
    "crates/runne-daemon-openai-effect/src/bounds.rs",
    "crates/runne-daemon-deepseek-effect/src/client.rs",
    "crates/runne-daemon-deepseek-effect/src/bounds.rs",
)


class CredentialSecretSurfaceValidatorTests(unittest.TestCase):
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

    def run_validator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--root", str(self.root)],
            capture_output=True,
            check=False,
            text=True,
        )

    def mutate(self, path: str, before: str, after: str) -> None:
        target = self.root / path
        source = target.read_text(encoding="utf-8")
        self.assertIn(before, source, f"fixture anchor missing in {path}")
        target.write_text(source.replace(before, after, 1), encoding="utf-8")

    def assert_rejected(self, code: str) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(code, result.stdout)

    def test_current_guarded_tree_is_accepted(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("credential secret surfaces: PASS", result.stdout)

    def test_renderer_projection_material_field_is_rejected(self) -> None:
        self.mutate(
            "apps/desktop/src/shared/api/platform/providers.ts",
            "  lastDisposition: ProviderCredentialDisposition | null\n}>",
            "  lastDisposition: ProviderCredentialDisposition | null\n"
            "  credential: string\n}>",
        )
        self.assert_rejected("SURFACE_RENDERER_PROJECTION")

    def test_tauri_intent_material_field_is_rejected(self) -> None:
        self.mutate(
            "apps/desktop/src-tauri/src/provider_credential_enrollment/command.rs",
            "    pub(crate) renderer_generation: u64,",
            "    pub(crate) renderer_generation: u64,\n    pub(crate) material: String,",
        )
        self.assert_rejected("SURFACE_TAURI_INTENT")

    def test_renderer_native_input_and_app_core_material_api_are_rejected(self) -> None:
        self.mutate(
            "apps/desktop/src/pages/providers/ui/ProvidersPage.vue",
            "  <section v-else aria-labelledby=\"providers-title\">",
            "  <section v-else aria-labelledby=\"providers-title\"><input />",
        )
        self.assert_rejected("SURFACE_RENDERER_PROMPT")
        self.reset_fixture()
        self.mutate(
            "crates/runne-app-core/src/lib_parts/providers.rs",
            "impl AppCore {",
            "pub struct PairProviderCredentialRequest;\nimpl AppCore {",
        )
        self.assert_rejected("SURFACE_APP_CORE")

    def test_runtime_client_and_contract_material_declarations_are_rejected(self) -> None:
        self.mutate(
            "crates/runne-runtime-client/src/canonical/provider_credentials.rs",
            "use runne_api::",
            "pub struct PairProviderCredentialRequest;\nuse runne_api::",
        )
        self.assert_rejected("SURFACE_RUNTIME_CLIENT_V1")
        self.reset_fixture()
        schema = self.root / "contracts/gocode-ui-client-2/schemas/provider-credentials-v1.schema.json"
        document = json.loads(schema.read_text(encoding="utf-8"))
        document["$defs"]["pairRequest"] = {"type": "object"}
        schema.write_text(json.dumps(document), encoding="utf-8")
        self.assert_rejected("SURFACE_PUBLIC_CONTRACT_V1")

    def test_public_http_body_extractor_is_rejected(self) -> None:
        self.mutate(
            "crates/runne-http/src/provider_credentials.rs",
            "async fn v1_unsupported(Extension(request_id): Extension<RequestId>) -> Response",
            "async fn v1_unsupported(Extension(request_id): Extension<RequestId>, "
            "axum::Json(material): axum::Json<String>) -> Response",
        )
        self.assert_rejected("SURFACE_PUBLIC_HTTP_V1")

    def test_secret_type_clone_and_public_borrow_are_rejected(self) -> None:
        path = "crates/runne-provider/src/credential/enrollment/service_protocol/types.rs"
        self.mutate(path, "pub struct CredentialMaterial", "#[derive(Clone)]\npub struct CredentialMaterial")
        self.mutate(
            path,
            "    /// Moves the zeroizing allocation",
            "    pub fn as_bytes(&self) -> &[u8] { &self.0 }\n"
            "    /// Moves the zeroizing allocation",
        )
        self.assert_rejected("SECRET_TYPE_TRAITS")
        self.assert_rejected("SECRET_PUBLIC_BORROW")

    def test_manual_clone_and_renamed_public_borrow_are_rejected(self) -> None:
        path = "crates/runne-provider/src/credential/enrollment/service_protocol/types.rs"
        self.mutate(
            path,
            "impl CredentialMaterial {",
            "impl Clone for CredentialMaterial {\n"
            "    fn clone(&self) -> Self { unreachable!() }\n"
            "}\nimpl CredentialMaterial {",
        )
        self.assert_rejected("SECRET_TYPE_TRAITS")
        self.reset_fixture()
        self.mutate(
            path,
            "    /// Moves the zeroizing allocation",
            "    pub fn leak(&self) -> &[u8] { unreachable!() }\n"
            "    /// Moves the zeroizing allocation",
        )
        self.assert_rejected("SECRET_PUBLIC_BORROW")

    def test_unbounded_secret_constructor_is_rejected(self) -> None:
        self.mutate(
            "crates/runne-provider/src/credential/enrollment/service_protocol/types.rs",
            "    /// Moves the zeroizing allocation",
            "    pub fn unchecked(value: Vec<u8>) -> Self { Self(Zeroizing::new(value)) }\n"
            "    /// Moves the zeroizing allocation",
        )
        self.assert_rejected("SECRET_UNBOUNDED_CONSTRUCTOR")

    def test_task2_zeroizing_decode_and_backend_patterns_are_guarded(self) -> None:
        mutations = (
            (
                "crates/runne-provider/src/credential/enrollment/service_protocol/codec.rs",
                "take_zeroizing_vec(bytes, &mut at)?",
                "take_vec(bytes, &mut at)?",
                "TASK2_WRITER_ZEROIZING_DECODE",
            ),
            (
                "crates/runne-provider/src/credential/enrollment/service_protocol/codec/reply.rs",
                "CredentialMaterial::from_wire(take_zeroizing_vec(bytes, at)?)?",
                "CredentialMaterial::from_bytes(take_vec(bytes, at)?)?",
                "TASK2_REPLY_ZEROIZING_DECODE",
            ),
            (
                "crates/runne-credential-service/src/keychain/native.rs",
                "let material = Zeroizing::new(material.bytes().to_vec());",
                "let material = material.bytes().to_vec();",
                "TASK2_KEYCHAIN_WRAP_FIRST",
            ),
            (
                "crates/runne-credential-service/src/service_backend.rs",
                "material: material.into_zeroizing(),",
                "material: Zeroizing::new(material.to_vec()),",
                "TASK2_MEMORY_MOVE_OWNERSHIP",
            ),
        )
        for path, before, after, code in mutations:
            with self.subTest(code=code):
                self.reset_fixture()
                self.mutate(path, before, after)
                self.assert_rejected(code)

    def test_task3_prompt_cleanup_route_cannot_be_removed(self) -> None:
        self.mutate(
            "apps/desktop/src-tauri/src/provider_credential_enrollment/host_prompt/macos/routes.rs",
            "fallback.finish_registered(id, Err(SecureCredentialPromptError::Unavailable));",
            "cleanup::finish(id);",
        )
        self.assert_rejected("TASK3_PROMPT_CLEANUP_ROUTE")

    def test_task4_call_state_and_frame_bound_cannot_be_removed(self) -> None:
        self.mutate(
            "crates/runne-macos-xpc/src/client/native/exchange.rs",
            "call.close_unknown(UnknownTerminal::Cancelled);",
            "drop(call);",
        )
        self.assert_rejected("TASK4_SINGLE_TERMINAL_CALL")
        self.reset_fixture()
        self.mutate(
            "crates/runne-macos-xpc/src/frame.rs",
            "bytes.len() > MAX_CREDENTIAL_SERVICE_FRAME_BYTES",
            "false",
        )
        self.assert_rejected("TASK4_FRAME_BOUND")


if __name__ == "__main__":
    unittest.main()
