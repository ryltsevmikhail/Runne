class CredentialServiceCoreDependencyTest(unittest.TestCase):
    PACKAGE = "runne-credential-service-core"

    def test_exact_contract_edges_fail_closed(self):
        self.assertEqual(
            {"runne-api", "runne-provider"},
            architecture.ALLOWED_RUST_DEPENDENCIES[self.PACKAGE],
        )
        validate = architecture.find_credential_service_core_dependency_violations
        self.assertEqual([], validate([self.package()]))

        normalized = self.package()
        normalized["dependencies"][1]["path"] = (
            "/repo/crates/runne-credential-service-core/../runne-api"
        )
        self.assertEqual([], validate([normalized]))

        for name, kind in (
            ("hyper", None), ("sqlx", None), ("libsqlite3-sys", None),
            ("tauri-runtime", None), ("arbitrary-dev-helper", "dev"),
            ("cc", "build"),
        ):
            package = self.package()
            package["dependencies"].append({"name": name, "kind": kind})
            actual_kind = kind or "normal"
            self.assertEqual(
                [f"{self.PACKAGE} -> {name} ({actual_kind}) is outside exact dependency allowlist"],
                validate([package]),
            )

        for field, value in (
            ("kind", "dev"), ("features", ["unexpected"]), ("rename", "rng"),
            ("optional", True), ("target", 'cfg(target_os = "macos")'),
            ("uses_default_features", False),
            ("source", "registry+https://example.invalid/index"),
            ("path", "/tmp/not-the-workspace/rand"), ("registry", "private"),
        ):
            package = self.package()
            package["dependencies"][0][field] = value
            violations = validate([package])
            if field == "kind":
                self.assertIn(
                    f"{self.PACKAGE} -> rand (dev) is outside exact dependency allowlist",
                    violations,
                )
                self.assertIn(
                    f"{self.PACKAGE} -> rand (normal) exact dependency is missing",
                    violations,
                )
            else:
                self.assertEqual(
                    [f"{self.PACKAGE} -> rand (normal) has forbidden dependency shape"],
                    violations,
                )

        expected_edges = (
            ("rand", "normal"), ("runne-api", "normal"),
            ("runne-provider", "normal"), ("subtle", "normal"),
            ("zeroize", "normal"),
            ("runne-provider", "dev"),
        )
        for index, (name, kind) in enumerate(expected_edges):
            package = self.package()
            del package["dependencies"][index]
            self.assertEqual(
                [f"{self.PACKAGE} -> {name} ({kind}) exact dependency is missing"],
                validate([package]),
            )

        package = self.package()
        package["dependencies"][4]["req"] = "*"
        self.assertEqual(
            [f"{self.PACKAGE} -> zeroize (normal) has forbidden dependency shape"],
            validate([package]),
        )

        missing_manifest = self.package()
        del missing_manifest["manifest_path"]
        self.assertIn(
            f"{self.PACKAGE} manifest_path is missing or noncanonical",
            validate([missing_manifest]),
        )
        for path in ("/tmp/foreign/crates/runne-api", None):
            package = self.package()
            package["dependencies"][1]["path"] = path
            self.assertEqual(
                [f"{self.PACKAGE} -> runne-api (normal) has forbidden dependency shape"],
                validate([package]),
            )
        self.assertEqual(
            [f"{self.PACKAGE} package is missing from workspace metadata"],
            validate([]),
        )

    @classmethod
    def package(cls):
        return {
            "name": cls.PACKAGE,
            "manifest_path": "/repo/crates/runne-credential-service-core/Cargo.toml",
            "dependencies": [
                cls.dependency("rand", req="=0.8.7", source=architecture.CARGO_REGISTRY_SOURCE),
                cls.dependency("runne-api", path="/repo/crates/runne-api"),
                cls.dependency("runne-provider", path="/repo/crates/runne-provider"),
                cls.dependency("subtle", req="=2.6.1", source=architecture.CARGO_REGISTRY_SOURCE),
                cls.dependency("zeroize", req="=1.9.0", source=architecture.CARGO_REGISTRY_SOURCE),
                cls.dependency("runne-provider", kind="dev", features=["test-support"], path="/repo/crates/runne-provider"),
            ],
        }

    @staticmethod
    def dependency(name, *, kind=None, req="*", features=None, source=None, path=None):
        return {
            "name": name, "kind": kind, "req": req, "features": features or [],
            "optional": False, "rename": None, "target": None,
            "uses_default_features": True, "source": source, "path": path,
            "registry": None,
        }
