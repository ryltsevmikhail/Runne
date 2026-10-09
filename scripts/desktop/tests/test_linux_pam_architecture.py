"""The Linux PAM edge stays a target-scoped adapter-to-FFI leaf."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "linux_pam_architecture", Path(__file__).parents[1] / "validate_architecture.py"
)
architecture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(architecture)


def workspace(root):
    crates = root.resolve() / "crates"
    return [
        {
            "name": "runne-platform-desktop",
            "manifest_path": str(crates / "runne-platform-desktop" / "Cargo.toml"),
            "dependencies": [{
                "name": "runne-linux-pam", "source": None, "req": "*", "kind": None,
                "rename": None, "optional": False, "uses_default_features": True,
                "features": [], "target": 'cfg(target_os = "linux")', "registry": None,
                "path": str(crates / "runne-linux-pam"),
            }],
        },
        {
            "name": "runne-linux-pam",
            "manifest_path": str(crates / "runne-linux-pam" / "Cargo.toml"),
            "dependencies": [
                dependency("libc", "^0.2"), dependency("zeroize", "=1.9.0"),
            ],
        },
    ]


def dependency(name, requirement, **changes):
    row = {
        "name": name, "source": architecture.CARGO_REGISTRY_SOURCE,
        "req": requirement, "kind": None, "rename": None, "optional": False,
        "uses_default_features": True, "features": [], "target": None,
        "registry": None, "path": None,
    }
    row.update(changes)
    return row


class LinuxPamArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def check(self, packages):
        return architecture.find_linux_pam_dependency_violations(packages, self.root)

    def test_accepts_only_the_exact_linux_adapter_to_leaf_shape(self):
        self.assertEqual([], self.check(workspace(self.root)))

    def test_rejects_wrong_owner_targets_duplicates_and_missing_edge(self):
        cases = []
        packages = workspace(self.root)
        edge = packages[0]["dependencies"].pop()
        packages.append({"name": "runne-unlisted-owner", "dependencies": [edge]})
        cases.append(("wrong owner", packages))
        packages = workspace(self.root)
        packages[0]["dependencies"][0]["target"] = None
        cases.append(("global edge", packages))
        packages = workspace(self.root)
        packages[0]["dependencies"][0]["target"] = 'cfg(target_os = "windows")'
        cases.append(("other target", packages))
        packages = workspace(self.root)
        packages[0]["dependencies"].append(copy.deepcopy(packages[0]["dependencies"][0]))
        cases.append(("duplicate edge", packages))
        packages = workspace(self.root)
        packages[0]["dependencies"].clear()
        cases.append(("missing edge", packages))
        for label, rows in cases:
            with self.subTest(label=label):
                self.assertTrue(self.check(rows))

    def test_rejects_edge_renames_optional_and_wrong_locations(self):
        changes = (
            {"rename": "pam"}, {"optional": True},
            {"path": "/other/crates/runne-linux-pam"},
            {"source": architecture.CARGO_REGISTRY_SOURCE},
            {"kind": "dev"}, {"kind": "build"},
        )
        for change in changes:
            rows = workspace(self.root)
            rows[0]["dependencies"][0].update(change)
            with self.subTest(change=change):
                self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows[1]["manifest_path"] = "/other/crates/runne-linux-pam/Cargo.toml"
        self.assertTrue(self.check(rows))

    def test_rejects_missing_or_duplicate_leaf_and_any_extra_dependency_kind(self):
        rows = workspace(self.root)
        rows[1]["dependencies"].append(dependency("runne-private", "*"))
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows[1]["dependencies"].append(dependency("runne-api", "*"))
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows[1]["dependencies"].append(dependency("helper", "=1", kind="dev"))
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows[1]["dependencies"].append(dependency("helper", "=1", kind="build"))
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows[1]["dependencies"].pop()
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows[1]["dependencies"][1] = copy.deepcopy(rows[1]["dependencies"][0])
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows.pop(1)
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows.append(copy.deepcopy(rows[1]))
        self.assertTrue(self.check(rows))

    def test_rejects_leaf_dependency_source_version_features_and_flags(self):
        changes = (
            {"source": "git+https://example.invalid/libc"},
            {"path": "/tmp/libc"}, {"registry": "private"},
            {"req": "*"}, {"features": ["extra"]},
            {"uses_default_features": False}, {"optional": True},
            {"rename": "system"}, {"target": 'cfg(target_os = "linux")'},
            {"kind": "dev"}, {"kind": "build"},
        )
        for change in changes:
            rows = workspace(self.root)
            rows[1]["dependencies"][0].update(change)
            with self.subTest(change=change):
                self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows[1]["dependencies"][1]["req"] = "^1.9"
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        rows[1]["dependencies"][0]["name"] = "substituted-libc"
        self.assertTrue(self.check(rows))
        rows = workspace(self.root)
        del rows[1]["dependencies"][0]["kind"]
        self.assertTrue(self.check(rows))

    def test_current_workspace_guard_and_real_architecture_lint_pass(self):
        metadata = architecture.load_workspace_metadata(ROOT)
        self.assertEqual(
            [], architecture.find_linux_pam_dependency_violations(metadata["packages"], ROOT)
        )
        result = subprocess.run(
            ["pnpm", "lint:architecture"], cwd=ROOT, capture_output=True,
            text=True, timeout=240,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
