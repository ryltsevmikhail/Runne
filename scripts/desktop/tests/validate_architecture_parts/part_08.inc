class CredentialKeychainBoundaryTest(unittest.TestCase):
    def test_service_dependency_shape_is_closed(self):
        target = 'cfg(target_os = "macos")'
        package = {
            "name": "runne-credential-service",
            "manifest_path": "/repo/crates/runne-credential-service/Cargo.toml",
            "dependencies": [
                {"name": name, "target": target if name in {
                    "core-foundation", "core-foundation-sys", "security-framework",
                    "security-framework-sys"
                } else None}
                for name in (
                    "hex", "runne-credential-service-core", "runne-macos-xpc",
                    "runne-provider", "zeroize", "core-foundation",
                    "core-foundation-sys", "security-framework", "security-framework-sys",
                )
            ],
        }
        validate = architecture.find_credential_service_dependency_violations
        self.assertEqual([], validate([package], Path("/repo")))
        package["dependencies"].append({"name": "serde", "target": None})
        self.assertNotEqual([], validate([package], Path("/repo")))

    def test_only_service_owns_exact_dpk_credential_symbols(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = root / "crates" / "runne-credential-service" / "src"
            service.mkdir(parents=True)
            policy = "\n".join((
                "SecItemAdd SecItemCopyMatching SecItemDelete",
                "kSecClassGenericPassword kSecAttrService kSecAttrAccount",
                "kSecAttrAccessGroup kSecAttrSynchronizable",
                "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
                "kSecUseDataProtectionKeychain",
                "758F9Z45SR.com.runne.credential-service",
            ))
            (service / "keychain.rs").write_text(policy, encoding="utf-8")
            validate = architecture.find_credential_keychain_boundary_violations
            self.assertEqual([], validate(root))

            foreign = root / "crates" / "runne" / "src"
            foreign.mkdir(parents=True)
            (foreign / "main.rs").write_text("SecItemAdd(query);\n", encoding="utf-8")
            self.assertNotEqual([], validate(root))

    def test_missing_policy_or_legacy_acl_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = root / "crates" / "runne-credential-service" / "src"
            service.mkdir(parents=True)
            source = service / "keychain.rs"
            for legacy_acl in ("SecAccessRef", "SecAccessCreate", "kSecAttrAccess"):
                source.write_text(f"SecItemAdd {legacy_acl}\n", encoding="utf-8")
                violations = architecture.find_credential_keychain_boundary_violations(root)
                self.assertGreaterEqual(len(violations), 2)
