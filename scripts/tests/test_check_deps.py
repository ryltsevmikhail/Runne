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
        manifests = list((SCRIPT_PATH.parents[1] / "crates").glob("*/Cargo.toml"))
        enabled = []
        for manifest in manifests:
            text = manifest.read_text(encoding="utf-8")
            dependency_lines = [
                line for line in text.splitlines()
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
                "features": [checker.PROJECT_OWNER_STORE_FEATURE],
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
