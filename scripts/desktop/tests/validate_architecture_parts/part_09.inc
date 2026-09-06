class NativeQualificationBoundaryTest(unittest.TestCase):
    def test_native_qualification_crate_has_a_closed_dependency_set(self):
        self.assertEqual(
            {
                "base64", "ed25519-dalek", "hex", "runne-api", "serde",
                "serde_json", "sha2",
            },
            architecture.NATIVE_QUALIFICATION_DEPENDENCIES,
        )
        self.assertEqual(
            [], architecture.find_native_qualification_dependency_violations(self.packages())
        )

    def test_rejects_dependency_shape_mutations(self):
        for label, index, field, value in (
            ("missing", 0, "delete", None),
            ("extra", 0, "name", "rand"),
            ("floating", 1, "req", "^2"),
            ("defaults", 7, "uses_default_features", True),
            ("feature", 5, "features", ["raw_value"]),
            ("target", 6, "target", 'cfg(target_os = "macos")'),
            ("path", 2, "path", "/tmp/hex"),
            ("API edge missing", 3, "delete", None),
            ("API edge registry", 3, "source", architecture.CARGO_REGISTRY_SOURCE),
            ("API edge renamed", 3, "rename", "api"),
            ("static assertion missing", 8, "delete", None),
            ("static assertion production edge", 8, "kind", None),
            ("static assertion floating", 8, "req", "^1"),
            ("AST parser missing", 9, "delete", None),
            ("AST parser production edge", 9, "kind", None),
            ("AST parser feature drift", 9, "features", ["full"]),
        ):
            with self.subTest(label=label):
                packages = self.packages()
                package = packages[0]
                if field == "delete":
                    del package["dependencies"][index]
                else:
                    package["dependencies"][index][field] = value
                self.assertNotEqual(
                    [], architecture.find_native_qualification_dependency_violations(packages)
                )

    def test_api_dependency_matches_the_metadata_package_not_a_path_suffix(self):
        packages = self.packages()
        packages[0]["dependencies"][3]["path"] = "/tmp/evil/crates/runne-api"
        self.assertNotEqual(
            [], architecture.find_native_qualification_dependency_violations(packages)
        )
        packages = self.packages()
        packages[0]["dependencies"][3]["path"] = "/repo/crates/../crates/runne-api"
        self.assertEqual(
            [], architecture.find_native_qualification_dependency_violations(packages)
        )

    def test_rejects_runtime_key_signer_filesystem_and_callback_surfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/runne-native-qualification/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub struct VerifiedQualificationFault;\n", encoding="utf-8")
            self.assertEqual([], architecture.find_native_qualification_violations(root))
            for forbidden in (
                "std::env::var(\"KEY\")",
                "use std::env as process_env; process_env::var(\"KEY\");",
                "std::fs::read(\"key\")",
                "use std::{fs as disk}; disk::read(\"key\");",
                "SigningKey::from_bytes(&key)",
                "pub fn verify_with<F: FnOnce()>(callback: F) {}",
                "pub fn verify_with<F>(callback: F) where F: FnMut() {}",
                "#[derive(Clone)] pub struct VerifiedQualificationFault;",
            ):
                source.write_text(forbidden, encoding="utf-8")
                self.assertNotEqual(
                    [], architecture.find_native_qualification_violations(root), forbidden
                )

    def test_rejects_manual_reusable_proof_trait_implementations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/runne-native-qualification/src/lib.rs"
            source.parent.mkdir(parents=True)
            implementations = (
                "impl Clone for VerifiedQualificationFault { fn clone(&self) -> Self { todo!() } }",
                "impl ::core::marker::Copy for VerifiedQualificationFault {}",
                "impl std :: clone :: Clone for VerifiedQualificationFault { fn clone(&self) -> Self { todo!() } }",
                "impl serde::Serialize for VerifiedQualificationFault { fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error> where S: serde::Serializer { todo!() } }",
                "impl serde :: ser :: Serialize for VerifiedQualificationFault { fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error> where S: serde::Serializer { todo!() } }",
                "use serde::Serialize; impl Serialize for VerifiedQualificationFault { fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error> where S: serde::Serializer { todo!() } }",
                "impl<'de> ::serde::Deserialize<'de> for VerifiedQualificationFault { fn deserialize<D>(_: D) -> Result<Self, D::Error> where D: serde::Deserializer<'de> { todo!() } }",
                "impl <'de> serde :: de :: Deserialize <'de> for VerifiedQualificationFault { fn deserialize<D>(_: D) -> Result<Self, D::Error> where D: serde::Deserializer<'de> { todo!() } }",
                "impl Clone for crate :: VerifiedQualificationFault { fn clone(&self) -> Self { todo!() } }",
                "impl serde::Serialize for crate :: model :: VerifiedQualificationFault { fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error> where S: serde::Serializer { todo!() } }",
            )
            for implementation in implementations:
                with self.subTest(implementation=implementation):
                    source.write_text(
                        "pub struct VerifiedQualificationFault;\n" + implementation,
                        encoding="utf-8",
                    )
                    self.assertNotEqual(
                        [], architecture.find_native_qualification_violations(root)
                    )

    def test_ticket_admission_dependency_is_target_only_and_desktop_owned(self):
        dependency = {
            "name": "runne-native-qualification", "kind": None, "req": "*",
            "features": [], "uses_default_features": True, "source": None,
            "path": "/repo/crates/runne-native-qualification", "registry": None,
            "target": 'cfg(target_os = "macos")', "rename": None, "optional": False,
        }
        desktop = {"name": "runne-desktop", "dependencies": [dependency]}
        self.assertEqual(
            [], architecture.find_native_qualification_admission_dependency_violations([desktop])
        )
        for label, package, field, value in (
            ("wrong owner", "runne-cli", None, None),
            ("not target scoped", "runne-desktop", "target", None),
            ("renamed", "runne-desktop", "rename", "faults"),
            ("features", "runne-desktop", "features", ["test-support"]),
            ("optional", "runne-desktop", "optional", True),
        ):
            with self.subTest(label=label):
                mutated = dict(dependency)
                if field:
                    mutated[field] = value
                row = {"name": package, "dependencies": [mutated]}
                self.assertNotEqual(
                    [],
                    architecture.find_native_qualification_admission_dependency_violations([row]),
                )

    def test_ticket_admission_has_no_renderer_cli_env_argv_or_storage_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / "apps/desktop/src-tauri/src/qualification_ticket.rs"
            owner.parent.mkdir(parents=True)
            owner.write_text(
                "use runne_native_qualification::PendingQualificationFault;\n",
                encoding="utf-8",
            )
            self.assertEqual(
                [], architecture.find_native_qualification_admission_surface_violations(root)
            )
            cases = (
                ("renderer", "apps/desktop/src/page.ts", "PendingQualificationFault"),
                ("cli", "crates/runne-cli/src/fault.rs", "runne_native_qualification"),
                ("module alias", "apps/desktop/src-tauri/src/lib_parts/commands.rs", "use crate::bundled_runtime::qualification_ticket as faults;"),
                ("host alias", "apps/desktop/src-tauri/src/lib_parts/commands.rs", "use crate::bundled_runtime::qualification_ticket::QualificationFaultHostState as Faults;"),
                ("state access", "apps/desktop/src-tauri/src/lib_parts/commands.rs", "fn leak(_: tauri::State<'_, QualificationFaultHostState>) {}"),
                ("tauri", "apps/desktop/src-tauri/src/qualification_ticket.rs", "#[tauri::command]"),
                ("environment", "apps/desktop/src-tauri/src/qualification_ticket.rs", "std::env::var(\"RUNNE_DPK\")"),
                ("argv", "apps/desktop/src-tauri/src/qualification_ticket.rs", "std::env::args_os()"),
                ("file", "apps/desktop/src-tauri/src/qualification_ticket.rs", "std::fs::read(\"ticket\")"),
                ("sqlite", "apps/desktop/src-tauri/src/qualification_ticket.rs", "profile.sqlite3"),
                ("run env", "apps/desktop/src-tauri/src/lib_parts/run.rs", "let qualification_faults = std::env::var(\"TICKET\");"),
                ("run argv", "apps/desktop/src-tauri/src/lib_parts/run.rs", "let qualification_faults =\n std::env::args_os();"),
                ("run file", "apps/desktop/src-tauri/src/lib_parts/run.rs", "let qualification_ticket = std::fs::read(\"ticket\");"),
                ("run sqlite", "apps/desktop/src-tauri/src/lib_parts/run.rs", "let qualification_faults = rusqlite::Connection::open(\"ticket.sqlite3\");"),
                ("bundled env", "apps/desktop/src-tauri/src/bundled_runtime.rs", "let qualification_ticket = std::env::var(\"TICKET\");"),
                ("bundled argv", "apps/desktop/src-tauri/src/bundled_runtime.rs", "let qualification_faults = std::env::args_os();"),
                ("bundled file", "apps/desktop/src-tauri/src/bundled_runtime.rs", "let qualification_ticket = std::fs::read(\"ticket\");"),
                ("bundled sqlite", "apps/desktop/src-tauri/src/bundled_runtime.rs", "let qualification_ticket = rusqlite::Connection::open(\"ticket.sqlite3\");"),
                ("forgeable bool", "apps/desktop/src-tauri/src/qualification_ticket.rs", "fn admit(bundle_is_protected: bool) {}"),
                ("raw getter", "apps/desktop/src-tauri/src/qualification_ticket.rs", "pub fn bytes(&self) -> &[u8] { &[] }"),
            )
            for label, relative, payload in cases:
                with self.subTest(label=label):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    baseline = path.read_text(encoding="utf-8") if path.exists() else ""
                    path.write_text(baseline + payload, encoding="utf-8")
                    self.assertNotEqual(
                        [], architecture.find_native_qualification_admission_surface_violations(root)
                    )
                    path.write_text(baseline, encoding="utf-8")

    @classmethod
    def packages(cls):
        rows = [
            cls.dependency("base64", "=0.22.1"),
            cls.dependency("ed25519-dalek", "=2.1.1"),
            cls.dependency("hex", "^0.4"),
            cls.dependency(
                "runne-api", "*", source=None,
                path="/repo/crates/runne-api",
            ),
            cls.dependency("serde", "=1.0.229", features=["derive"]),
            cls.dependency("serde_json", "=1.0.151"),
            cls.dependency("sha2", "=0.10.8"),
            cls.dependency(
                "jsonschema", "=0.18.0", kind="dev",
                features=["draft202012"], defaults=False,
            ),
            cls.dependency("static_assertions", "=1.1.0", kind="dev"),
            cls.dependency(
                "syn", "^2", kind="dev", features=["extra-traits", "full", "visit"],
            ),
        ]
        return [
            {
                "name": architecture.NATIVE_QUALIFICATION_PACKAGE,
                "manifest_path": "/repo/crates/runne-native-qualification/Cargo.toml",
                "dependencies": rows,
            },
            {
                "name": "runne-api",
                "manifest_path": "/repo/crates/runne-api/Cargo.toml",
                "dependencies": [],
            },
        ]

    @staticmethod
    def dependency(
        name, req, *, kind=None, features=None, defaults=True,
        source=architecture.CARGO_REGISTRY_SOURCE, path=None,
    ):
        return {
            "name": name, "kind": kind, "req": req, "features": features or [],
            "uses_default_features": defaults, "source": source,
            "path": path, "registry": None, "target": None, "rename": None,
            "optional": False,
        }
