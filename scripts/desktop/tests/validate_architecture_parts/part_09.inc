class NativeQualificationBoundaryTest(unittest.TestCase):
    def test_native_qualification_crate_has_a_closed_dependency_set(self):
        self.assertEqual(
            {"base64", "ed25519-dalek", "hex", "serde", "serde_json", "sha2"},
            architecture.NATIVE_QUALIFICATION_DEPENDENCIES,
        )
        self.assertEqual(
            [], architecture.find_native_qualification_dependency_violations([self.package()])
        )

    def test_rejects_dependency_shape_mutations(self):
        for label, index, field, value in (
            ("missing", 0, "delete", None),
            ("extra", 0, "name", "rand"),
            ("floating", 1, "req", "^2"),
            ("defaults", 6, "uses_default_features", True),
            ("feature", 4, "features", ["raw_value"]),
            ("target", 5, "target", 'cfg(target_os = "macos")'),
            ("path", 2, "path", "/tmp/hex"),
        ):
            with self.subTest(label=label):
                package = self.package()
                if field == "delete":
                    del package["dependencies"][index]
                else:
                    package["dependencies"][index][field] = value
                self.assertNotEqual(
                    [], architecture.find_native_qualification_dependency_violations([package])
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

    @classmethod
    def package(cls):
        rows = [
            cls.dependency("base64", "=0.22.1"),
            cls.dependency("ed25519-dalek", "=2.1.1"),
            cls.dependency("hex", "^0.4"),
            cls.dependency("serde", "=1.0.229", features=["derive"]),
            cls.dependency("serde_json", "=1.0.151"),
            cls.dependency("sha2", "=0.10.8"),
            cls.dependency(
                "jsonschema", "=0.18.0", kind="dev",
                features=["draft202012"], defaults=False,
            ),
        ]
        return {
            "name": architecture.NATIVE_QUALIFICATION_PACKAGE,
            "manifest_path": "/repo/crates/runne-native-qualification/Cargo.toml",
            "dependencies": rows,
        }

    @staticmethod
    def dependency(name, req, *, kind=None, features=None, defaults=True):
        return {
            "name": name, "kind": kind, "req": req, "features": features or [],
            "uses_default_features": defaults, "source": architecture.CARGO_REGISTRY_SOURCE,
            "path": None, "registry": None, "target": None, "rename": None,
            "optional": False,
        }
