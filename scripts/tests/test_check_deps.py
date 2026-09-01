import importlib.util
import pathlib
import sys
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "check-deps.py"
SPEC = importlib.util.spec_from_file_location("check_deps", SCRIPT_PATH)
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


class CheckDepsTests(unittest.TestCase):
    def test_runne_api_dependencies_are_exact_and_native_free(self) -> None:
        name = "runne-api"
        expected = {
            "base64",
            "ed25519-dalek",
            "hex",
            "hmac",
            "jsonschema",
            "runne-domain",
            "runne-plugin-protocol",
            "serde",
            "serde_json",
            "sha2",
            "subtle",
            "zeroize",
        }
        self.assertEqual(checker.POLICIES[name], expected)
        self.assertFalse(
            expected
            & {
                "libc",
                "nix",
                "reqwest",
                "runne-macos-process-identity",
                "runne-native-enrollment-authority",
                "runne-platform-desktop",
                "runne-platform-ports",
                "rustix",
                "security-framework",
            }
        )

    def test_runne_platform_allows_platform_ports(self) -> None:
        self.assertIn("runne-platform-ports", checker.POLICIES["runne-platform"])

    def test_project_owner_authority_dependencies_are_exact_and_isolated(self) -> None:
        name = "runne-project-owner-authority"
        forbidden = {"runne-cli", "runne-store", "runne-runtime"}
        self.assertEqual(checker.EXACT_VERSION_POLICIES[name], checker.POLICIES[name])
        self.assertFalse(checker.POLICIES[name] & forbidden)

    def test_release_authority_dependencies_are_exact_and_isolated(self) -> None:
        name = "runne-release-authority"
        forbidden = {"runne-cli", "runne-store", "runne-runtime"}
        self.assertEqual(checker.EXACT_VERSION_POLICIES[name], checker.POLICIES[name])
        self.assertFalse(checker.POLICIES[name] & forbidden)

    def test_native_enrollment_authority_dependencies_are_narrow_and_isolated(self) -> None:
        name = "runne-native-enrollment-authority"
        self.assertEqual(
            checker.POLICIES[name],
            {
                "runne-api",
                "runne-macos-process-identity",
                "runne-provider",
            },
        )
        self.assertFalse(
            checker.POLICIES[name]
            & {
                "runne-cli",
                "runne-daemon",
                "runne-platform-desktop",
                "runne-platform-ports",
                "runne-release-authority",
                "runne-runtime-client",
                "runne-secure-store",
            }
        )

    def test_native_enrollment_authority_allows_only_writer_side_consumers(self) -> None:
        dependency = {
            "name": "runne-native-enrollment-authority",
            "kind": None,
        }
        allowed = [
            {"name": "runne-cli", "dependencies": [dependency]},
            {"name": "runne-secure-store", "dependencies": [dependency]},
        ]
        self.assertFalse(checker.native_enrollment_authority_consumer_errors([]))
        self.assertFalse(
            checker.native_enrollment_authority_consumer_errors(allowed)
        )
        for package in (
            "runne-api",
            "runne-daemon",
            "runne-platform-desktop",
            "runne-platform-ports",
            "runne-provider",
            "runne-runtime-client",
        ):
            with self.subTest(package=package):
                self.assertEqual(
                    [
                        "FAIL: runne-native-enrollment-authority has forbidden "
                        f"production consumers: ['{package}']"
                    ],
                    checker.native_enrollment_authority_consumer_errors(
                        [{"name": package, "dependencies": [dependency]}]
                    ),
                )

    def test_native_enrollment_authority_ignores_dev_only_consumers(self) -> None:
        packages = [
            {
                "name": "runne-daemon",
                "dependencies": [
                    {
                        "name": "runne-native-enrollment-authority",
                        "kind": "dev",
                    }
                ],
            }
        ]
        self.assertFalse(
            checker.native_enrollment_authority_consumer_errors(packages)
        )

    def test_release_authority_boundary_requires_the_cli_only(self) -> None:
        packages = [
            {"name": "runne-release-authority", "manifest_path": __file__, "dependencies": []},
            {"name": "runne-cli", "dependencies": [{"name": "runne-release-authority", "kind": None}]},
        ]
        self.assertFalse(checker.release_authority_boundary_errors(packages))

    def test_internal_authority_edges_reject_rename_target_and_external_path(self) -> None:
        good = {"name": "runne-release-authority", "dependencies": [{"name": "runne-promotion-contracts", "kind": None, "target": None, "rename": None, "optional": False, "path": "/repo/crates/runne-promotion-contracts"}]}
        self.assertFalse(checker.internal_authority_edge_errors([good]))
        for field, value in (("rename", "contracts"), ("target", "cfg(unix)"), ("path", "/external/promotion-contracts")):
            bad = {**good, "dependencies": [{**good["dependencies"][0], field: value}]}
            self.assertTrue(checker.internal_authority_edge_errors([bad]))

    def test_owner_backup_argon2_feature_is_pinned_for_zeroization(self) -> None:
        manifest = (SCRIPT_PATH.parents[1] / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn(
            'argon2 = { version = "=0.5.3", features = ["zeroize"] }',
            manifest,
        )

    def test_only_cli_enables_the_project_owner_store_feature(self) -> None:
        self.assertEqual(checker.PROJECT_OWNER_STORE_OWNER, "runne-cli")
        self.assertEqual(checker.PROJECT_OWNER_STORE_FEATURE, "project-owner-key-store")
        self.assertEqual(
            checker.PROJECT_OWNER_STORE_FEATURES,
            {"project-owner-key-store", "provider-credential-broker-writer"},
        )
        manifests = list((SCRIPT_PATH.parents[1] / "crates").glob("*/Cargo.toml"))
        enabled = []
        for manifest in manifests:
            text = manifest.read_text(encoding="utf-8")
            _, marker, remainder = text.partition("[dependencies]")
            if not marker:
                continue
            dependencies = remainder.split("\n[", 1)[0]
            dependency_lines = [
                line for line in dependencies.splitlines()
                if line.startswith("runne-secure-store =")
            ]
            if not dependency_lines:
                continue
            self.assertEqual(len(dependency_lines), 1, manifest)
            self.assertIn("default-features = false", dependency_lines[0], manifest)
            if checker.PROJECT_OWNER_STORE_FEATURE in dependency_lines[0]:
                enabled.append(manifest.parent.name)
        self.assertEqual(enabled, ["runne-cli"])

    def test_owner_declaration_policy_rejects_non_cli_dev_rename_target_and_missing_cli(self) -> None:
        owner = {
            "name": "runne-cli",
            "dependencies": [{
                "name": "runne-secure-store", "kind": None, "target": None,
                "rename": None, "optional": False, "uses_default_features": False,
                "path": "/repo/crates/runne-secure-store",
                "features": sorted(checker.PROJECT_OWNER_STORE_FEATURES),
            }],
        }
        self.assertFalse(checker.project_owner_store_declaration_errors([owner]))
        for mutation in (
            {"name": "runne-runtime", "kind": None, "target": None, "rename": None, "optional": False, "uses_default_features": False, "path": "/repo/crates/runne-secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "runne-cli", "kind": "dev", "target": None, "rename": None, "optional": False, "uses_default_features": False, "path": "/repo/crates/runne-secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "runne-cli", "kind": None, "target": None, "rename": "owner_store", "optional": False, "uses_default_features": False, "path": "/repo/crates/runne-secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "runne-cli", "kind": None, "target": "cfg(target_os = \"macos\")", "rename": None, "optional": False, "uses_default_features": False, "path": "/repo/crates/runne-secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "runne-cli", "kind": None, "target": None, "rename": None, "optional": True, "uses_default_features": False, "path": "/repo/crates/runne-secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "runne-cli", "kind": None, "target": None, "rename": None, "optional": False, "uses_default_features": False, "path": "/external/secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
        ):
            package = {"name": mutation.pop("name"), "dependencies": [{"name": "runne-secure-store", **mutation}]}
            self.assertTrue(checker.project_owner_store_declaration_errors([package]))

    def test_non_owner_dev_test_support_declaration_is_allowed(self) -> None:
        owner = {
            "name": "runne-cli",
            "dependencies": [{
                "name": "runne-secure-store", "kind": None, "target": None,
                "rename": None, "optional": False, "uses_default_features": False,
                "path": "/repo/crates/runne-secure-store",
                "features": sorted(checker.PROJECT_OWNER_STORE_FEATURES),
            }],
        }
        package = {
            "name": "runne-app-core",
            "dependencies": [{
                "name": "runne-secure-store", "kind": "dev", "target": None,
                "rename": None, "optional": False, "uses_default_features": False,
                "path": "/repo/crates/runne-secure-store", "features": ["test-support"],
            }],
        }
        self.assertFalse(
            checker.project_owner_store_declaration_errors([owner, package])
        )
        package["dependencies"][0]["kind"] = None
        self.assertTrue(
            checker.project_owner_store_declaration_errors([owner, package])
        )

    def test_owner_consumer_scan_rejects_all_metadata_target_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            forbidden = root / "apps/desktop/src-tauri/src"
            allowed = root / "crates/runne-cli/src"
            forbidden.mkdir(parents=True)
            allowed.mkdir(parents=True)
            manifest = forbidden.parent / "Cargo.toml"
            manifest.write_text("[package]", encoding="utf-8")
            (forbidden / "main.rs").write_text("use runne_secure_store::*;", encoding="utf-8")
            (forbidden / "authority.rs").write_text("store.sign_active(reference, transcript);", encoding="utf-8")
            (allowed / "authority.rs").write_text("use runne_secure_store::ProjectOwnerKeyStore;", encoding="utf-8")
            packages = [
                {"name": "runne-desktop", "manifest_path": str(manifest), "targets": [{"src_path": str(forbidden / "main.rs")} ]},
                {"name": "runne-cli", "manifest_path": str(allowed.parent / "Cargo.toml"), "targets": []},
            ]
            errors = checker.project_owner_store_consumer_errors(packages)
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("apps/desktop/src-tauri/src" in error for error in errors))

    def test_owner_consumer_scan_allows_generic_store_operation_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "crates/runne-store/src/approvals.rs"
            source.parent.mkdir(parents=True)
            manifest = source.parents[1] / "Cargo.toml"
            manifest.write_text("[package]", encoding="utf-8")
            source.write_text("fn create_pending() {}", encoding="utf-8")
            packages = [{
                "name": "runne-store",
                "manifest_path": str(manifest),
                "targets": [{"src_path": str(source)}],
            }]
            self.assertFalse(checker.project_owner_store_consumer_errors(packages))


if __name__ == "__main__":
    unittest.main()
