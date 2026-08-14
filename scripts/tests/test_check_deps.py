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
    def test_gocode_platform_allows_platform_ports(self) -> None:
        self.assertIn("gocode-platform-ports", checker.POLICIES["gocode-platform"])

    def test_project_owner_authority_dependencies_are_exact_and_isolated(self) -> None:
        name = "gocode-project-owner-authority"
        forbidden = {"gocode-cli", "gocode-store", "gocode-runtime"}
        self.assertEqual(checker.EXACT_VERSION_POLICIES[name], checker.POLICIES[name])
        self.assertFalse(checker.POLICIES[name] & forbidden)

    def test_release_authority_dependencies_are_exact_and_isolated(self) -> None:
        name = "gocode-release-authority"
        forbidden = {"gocode-cli", "gocode-store", "gocode-runtime"}
        self.assertEqual(checker.EXACT_VERSION_POLICIES[name], checker.POLICIES[name])
        self.assertFalse(checker.POLICIES[name] & forbidden)

    def test_release_authority_boundary_requires_the_cli_only(self) -> None:
        packages = [
            {"name": "gocode-release-authority", "manifest_path": __file__, "dependencies": []},
            {"name": "gocode-cli", "dependencies": [{"name": "gocode-release-authority", "kind": None}]},
        ]
        self.assertFalse(checker.release_authority_boundary_errors(packages))

    def test_internal_authority_edges_reject_rename_target_and_external_path(self) -> None:
        good = {"name": "gocode-release-authority", "dependencies": [{"name": "gocode-promotion-contracts", "kind": None, "target": None, "rename": None, "optional": False, "path": "/repo/crates/gocode-promotion-contracts"}]}
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
        self.assertEqual(checker.PROJECT_OWNER_STORE_OWNER, "gocode-cli")
        self.assertEqual(checker.PROJECT_OWNER_STORE_FEATURE, "project-owner-key-store")
        manifests = list((SCRIPT_PATH.parents[1] / "crates").glob("*/Cargo.toml"))
        enabled = []
        for manifest in manifests:
            text = manifest.read_text(encoding="utf-8")
            dependency_lines = [
                line for line in text.splitlines()
                if line.startswith("gocode-secure-store =")
            ]
            if not dependency_lines:
                continue
            self.assertEqual(len(dependency_lines), 1, manifest)
            self.assertIn("default-features = false", dependency_lines[0], manifest)
            if checker.PROJECT_OWNER_STORE_FEATURE in dependency_lines[0]:
                enabled.append(manifest.parent.name)
        self.assertEqual(enabled, ["gocode-cli"])

    def test_owner_declaration_policy_rejects_non_cli_dev_rename_target_and_missing_cli(self) -> None:
        owner = {
            "name": "gocode-cli",
            "dependencies": [{
                "name": "gocode-secure-store", "kind": None, "target": None,
                "rename": None, "optional": False, "uses_default_features": False,
                "path": "/repo/crates/secure-store",
                "features": [checker.PROJECT_OWNER_STORE_FEATURE],
            }],
        }
        self.assertFalse(checker.project_owner_store_declaration_errors([owner]))
        for mutation in (
            {"name": "gocode-runtime", "kind": None, "target": None, "rename": None, "optional": False, "uses_default_features": False, "path": "/repo/crates/secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "gocode-cli", "kind": "dev", "target": None, "rename": None, "optional": False, "uses_default_features": False, "path": "/repo/crates/secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "gocode-cli", "kind": None, "target": None, "rename": "owner_store", "optional": False, "uses_default_features": False, "path": "/repo/crates/secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "gocode-cli", "kind": None, "target": "cfg(target_os = \"macos\")", "rename": None, "optional": False, "uses_default_features": False, "path": "/repo/crates/secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "gocode-cli", "kind": None, "target": None, "rename": None, "optional": True, "uses_default_features": False, "path": "/repo/crates/secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
            {"name": "gocode-cli", "kind": None, "target": None, "rename": None, "optional": False, "uses_default_features": False, "path": "/external/secure-store", "features": [checker.PROJECT_OWNER_STORE_FEATURE]},
        ):
            package = {"name": mutation.pop("name"), "dependencies": [{"name": "gocode-secure-store", **mutation}]}
            self.assertTrue(checker.project_owner_store_declaration_errors([package]))

    def test_owner_consumer_scan_rejects_all_metadata_target_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            forbidden = root / "apps/desktop/src-tauri/src"
            allowed = root / "crates/gocode-cli/src"
            forbidden.mkdir(parents=True)
            allowed.mkdir(parents=True)
            manifest = forbidden.parent / "Cargo.toml"
            manifest.write_text("[package]", encoding="utf-8")
            (forbidden / "main.rs").write_text("use gocode_secure_store::*;", encoding="utf-8")
            (forbidden / "authority.rs").write_text("store.sign_active(reference, transcript);", encoding="utf-8")
            (allowed / "authority.rs").write_text("use gocode_secure_store::ProjectOwnerKeyStore;", encoding="utf-8")
            packages = [
                {"name": "gocode-desktop", "manifest_path": str(manifest), "targets": [{"src_path": str(forbidden / "main.rs")} ]},
                {"name": "gocode-cli", "manifest_path": str(allowed.parent / "Cargo.toml"), "targets": []},
            ]
            errors = checker.project_owner_store_consumer_errors(packages)
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("apps/desktop/src-tauri/src" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
