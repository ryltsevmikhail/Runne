"""The shared policy loader may not acquire runtime or native authority edges."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "bootstrap_policy_architecture", Path(__file__).parents[1] / "validate_architecture.py"
)
architecture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(architecture)


def package():
    shapes = (
        ("runne-api", "*", [], None),
        ("runne-macos-file-security", "*", [], 'cfg(target_os = "macos")'),
        ("serde", "=1.0.229", ["derive"], None),
        ("serde_json", "=1.0.151", [], None),
        ("sha2", "=0.10.8", [], None),
        ("hex", "^0.4", [], None),
        ("rustix", "=1.1.4", ["fs"], 'cfg(target_os = "macos")'),
    )
    return {
        "name": architecture.BOOTSTRAP_POLICY_PACKAGE,
        "manifest_path": "/repo/crates/runne-qualification-bootstrap-policy/Cargo.toml",
        "features": {},
        "dependencies": [
            {"name": name, "req": req, "features": features, "target": target,
             "kind": None, "uses_default_features": True, "optional": False,
             "source": None if name.startswith("runne-") else architecture.CARGO_REGISTRY_SOURCE,
             "path": f"/repo/crates/{name}" if name.startswith("runne-") else None,
             "registry": None, "rename": None}
            for name, req, features, target in shapes
        ],
    }


class BootstrapPolicyArchitectureTests(unittest.TestCase):
    def check(self, row):
        return architecture.find_bootstrap_policy_dependency_violations([row], Path("/repo"))

    def test_exact_readonly_loader_dependencies(self):
        self.assertEqual([], self.check(package()))

    def test_feature_source_target_and_authority_edges_are_rejected(self):
        for field, value in (("features", ["test-support"]), ("optional", True),
                             ("kind", "build"), ("rename", "policy"),
                             ("path", "/other/api")):
            row = package()
            row["dependencies"][0][field] = value
            with self.subTest(field=field):
                self.assertTrue(self.check(row))
        row = package()
        row["dependencies"][-1]["target"] = None
        self.assertTrue(self.check(row))
        for name in ("runne-runtime", "runne-provider", "runne-macos-xpc", "reqwest"):
            row = package()
            row["dependencies"].append({"name": name})
            self.assertTrue(self.check(row))
        row = package()
        row["features"] = {"test-support": []}
        self.assertTrue(self.check(row))

    def test_missing_duplicated_or_relocated_loader_is_rejected(self):
        check = architecture.find_bootstrap_policy_dependency_violations
        self.assertTrue(check([], Path("/repo")))
        self.assertTrue(check([package(), package()], Path("/repo")))
        row = package()
        row["manifest_path"] = "/other/Cargo.toml"
        self.assertTrue(self.check(row))

    def test_native_adapter_cannot_gain_runtime_dependencies_or_features(self):
        check = architecture.find_macos_file_security_dependency_violations
        row = {"name": "runne-macos-file-security", "features": {},
               "manifest_path": "/repo/crates/runne-macos-file-security/Cargo.toml",
               "dependencies": [{"name": "cc", "kind": "build", "req": "=1.4.0",
                                 "source": architecture.CARGO_REGISTRY_SOURCE}]}
        self.assertEqual([], check([row], Path("/repo")))
        row["dependencies"].append({"name": "runne-runtime"})
        self.assertTrue(check([row], Path("/repo")))
        row["dependencies"].pop()
        row["features"] = {"test-support": []}
        self.assertTrue(check([row], Path("/repo")))


if __name__ == "__main__":
    unittest.main()
