import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).parents[1] / "validate_architecture.py"
SPEC = importlib.util.spec_from_file_location("validate_architecture", MODULE_PATH)
architecture = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(architecture)


class RustDependencyRulesTest(unittest.TestCase):
    def test_allows_documented_dependency_direction(self):
        violations = architecture.find_rust_dependency_violations(
            {
                "gocode-desktop": {"gocode-app-core", "gocode-platform-desktop"},
                "gocode-app-core": {"gocode-runtime-client", "gocode-local-store"},
                "gocode-platform-desktop": {"gocode-platform-ports"},
            }
        )

        self.assertEqual([], violations)

    def test_rejects_platform_implementation_importing_app_core(self):
        violations = architecture.find_rust_dependency_violations(
            {"gocode-platform-desktop": {"gocode-app-core"}}
        )

        self.assertEqual(
            ["gocode-platform-desktop -> gocode-app-core is forbidden"],
            violations,
        )

    def test_secure_store_allows_only_public_identity_and_acl_wrapper(self):
        allowed = architecture.find_rust_dependency_violations(
            {
                "gocode-secure-store": {
                    "gocode-api",
                    "gocode-macos-keychain-acl",
                }
            }
        )
        forbidden = architecture.find_rust_dependency_violations(
            {"gocode-secure-store": {"gocode-runtime"}}
        )

        self.assertEqual([], allowed)
        self.assertEqual(
            ["gocode-secure-store -> gocode-runtime is forbidden"],
            forbidden,
        )

    def test_local_store_allows_only_the_audited_sqlite_identity_shim(self):
        allowed = architecture.find_rust_dependency_violations(
            {
                "gocode-local-store": {
                    "gocode-api",
                    "gocode-sqlite-native-identity",
                }
            }
        )
        forbidden = architecture.find_rust_dependency_violations(
            {"gocode-local-store": {"gocode-runtime"}}
        )

        self.assertEqual([], allowed)
        self.assertEqual(
            ["gocode-local-store -> gocode-runtime is forbidden"], forbidden
        )


class ProviderTerminalPersistenceBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, relative_path: str, source: str):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def test_rejects_raw_terminal_commit_request_outside_runtime_boundary(self):
        self.write(
            "crates/gocode-daemon/src/provider.rs",
            """
            use gocode_application::provider::ProviderTerminalCommitRequest;
            fn bypass(request: ProviderTerminalCommitRequest) {}
            """,
        )

        violations = architecture.find_provider_terminal_persistence_violations(
            self.root
        )

        self.assertEqual(
            [
                "crates/gocode-daemon/src/provider.rs accesses raw provider terminal "
                "persistence outside the runtime-owned boundary"
            ],
            violations,
        )

    def test_allows_application_store_and_runtime_persistence_implementation(self):
        source = "struct ProviderTerminalCommitRequest;"
        for relative_path in architecture.PROVIDER_TERMINAL_PERSISTENCE_ALLOWED:
            self.write(relative_path.as_posix(), source)

        violations = architecture.find_provider_terminal_persistence_violations(
            self.root
        )

        self.assertEqual([], violations)

    def test_rejects_application_alias_factory_bypass(self):
        self.write(
            "crates/gocode-application/src/provider/execution.rs",
            """
            use gocode_runtime::provider_execution::ProviderTerminalCommitRequest as Raw;
            pub fn bypass() -> Raw { unimplemented!() }
            """,
        )

        violations = architecture.find_provider_terminal_persistence_violations(
            self.root
        )

        self.assertEqual(
            [
                "crates/gocode-application/src/provider/execution.rs accesses raw "
                "provider terminal persistence outside the runtime-owned boundary"
            ],
            violations,
        )

    def test_rejects_terminal_test_support_on_production_dependency(self):
        packages = [
            {
                "name": "gocode-daemon",
                "dependencies": [
                    {
                        "name": "gocode-runtime",
                        "kind": None,
                        "features": ["provider-terminal-test-support"],
                    }
                ],
            }
        ]

        self.assertEqual(
            [
                "gocode-daemon enables provider-terminal-test-support outside "
                "dev-dependencies"
            ],
            architecture.find_provider_terminal_test_feature_violations(packages),
        )


class ProtectedAdmissionSurfaceTest(unittest.TestCase):
    def test_rejects_ordinary_admission_result_and_unverified_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/gocode-api/src/protected_activation/root_admission.rs"
            control = root / "crates/gocode-api/src/protected_activation/root_handle_control.rs"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(
                "pub struct ProtectedRootHandleAdmission {}\n", encoding="utf-8"
            )
            control.write_text(
                "impl RootHandleTransferResult {\n"
                "  pub fn admitted(value: RootHandleAdmission) -> Self { todo!() }\n"
                "  pub fn into_admission(self) -> ProtectedRootHandleAdmission { todo!() }\n"
                "}\n",
                encoding="utf-8",
            )
            self.assertEqual(
                [
                    "crates/gocode-api/src/protected_activation/root_handle_control.rs accepts ordinary admission into a protected result",
                    "crates/gocode-api/src/protected_activation/root_handle_control.rs promotes an unverified result into protected provenance",
                ],
                architecture.find_protected_admission_surface_violations(root),
            )

    def test_rejects_server_carrier_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/gocode-api/src/protected_activation/root_admission.rs"
            carrier = root / "crates/gocode-api/src/protected_activation/root_bind_transport.rs"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(
                "pub struct ProtectedRootHandleAdmission {}\n", encoding="utf-8"
            )
            carrier.write_text(
                "impl RootBindAdmission {\n"
                "  pub fn into_protected(self) -> ProtectedRootHandleAdmission { todo!() }\n"
                "}\n",
                encoding="utf-8",
            )
            self.assertEqual(
                [
                    "crates/gocode-api/src/protected_activation/root_bind_transport.rs promotes the untrusted server carrier"
                ],
                architecture.find_protected_admission_surface_violations(root),
            )

    def test_rejects_public_raw_or_clone_or_serde_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/gocode-api/src/protected_activation/root_admission.rs"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(
                "pub struct ProtectedRootHandleAdmission {}\n"
                "impl ProtectedRootHandleAdmission { pub fn admission_bytes(&self) -> &[u8] { &[] } }\n",
                encoding="utf-8",
            )
            self.assertEqual(
                ["crates/gocode-api/src/protected_activation/root_admission.rs exposes raw protected-admission surface"],
                architecture.find_protected_admission_surface_violations(root),
            )

    def test_rejects_borrowed_string_encoder_on_the_wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/gocode-api/src/protected_activation/root_admission.rs"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(
                "pub struct ProtectedRootHandleAdmission {}\n"
                "impl ProtectedRootHandleAdmission { pub fn encode_root_bind_transport(&self) -> String { String::new() } }\n",
                encoding="utf-8",
            )
            self.assertTrue(
                architecture.find_protected_admission_surface_violations(root)
            )

    def test_rejects_clone_and_serde_derivations_on_the_wrapper(self):
        for derive in ("Clone", "Serialize", "Deserialize"):
            with self.subTest(derive=derive), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "crates/gocode-api/src/protected_activation/root_admission.rs"
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    f"#[derive({derive})]\npub struct ProtectedRootHandleAdmission {{}}\n",
                    encoding="utf-8",
                )
                self.assertTrue(
                    architecture.find_protected_admission_surface_violations(root)
                )

    def test_rejects_later_manual_traits_and_borrowed_transport_receiver(self):
        cases = (
            "impl Clone for ProtectedRootHandleAdmission {}",
            "impl Serialize for ProtectedRootHandleAdmission {}",
            "impl Deserialize for ProtectedRootHandleAdmission {}",
            "impl Deref for ProtectedRootHandleAdmission {}",
            "impl AsRef<[u8]> for ProtectedRootHandleAdmission {}",
            "impl ProtectedRootHandleAdmission { pub fn into_root_bind_transport(&self) {} }",
        )
        for surface in cases:
            with self.subTest(surface=surface), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "crates/gocode-api/src/protected_activation/root_admission.rs"
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(
                    "pub struct ProtectedRootHandleAdmission {}\n" + surface,
                    encoding="utf-8",
                )
                self.assertTrue(
                    architecture.find_protected_admission_surface_violations(root)
                )
