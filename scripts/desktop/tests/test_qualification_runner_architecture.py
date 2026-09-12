import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("architecture_runner", Path(__file__).parents[1] / "validate_architecture.py")
architecture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(architecture)


def dependency(name, req, features=(), target=None, kind=None):
    return {"name": name, "req": req, "features": list(features), "target": target,
            "kind": kind, "uses_default_features": True, "optional": False,
            "source": None if name.startswith("runne-") else architecture.CARGO_REGISTRY_SOURCE,
            "path": f"/repo/crates/{name}" if name.startswith("runne-") else None,
            "registry": None, "rename": None}


def packages():
    return [
        {"name": "runne-native-qualification", "manifest_path": "/repo/crates/runne-native-qualification/Cargo.toml"},
        {"name": "runne-qualification-runner", "features": {}, "dependencies": [
            dependency("runne-native-qualification", "*"),
            dependency("runne-sqlite-native-identity", "*"),
            dependency("runne-sqlite-handle-identity", "*"),
            dependency("rusqlite", "=0.34.0", ("bundled",)),
            dependency("rustix", "=1.1.4", ("fs", "process"), "cfg(unix)"),
        ]},
    ]


class RunnerArchitectureTests(unittest.TestCase):
    def test_exact_persistence_dependencies_are_allowed(self):
        self.assertEqual([], architecture.find_qualification_runner_dependency_violations(packages()))

    def test_production_dependency_mutations_are_rejected(self):
        for field, value in [("features", ["test-support"]), ("kind", "build"), ("optional", True), ("rename", "facts"), ("path", "/other/native")]:
            rows = packages()
            rows[1]["dependencies"][0][field] = value
            with self.subTest(field=field):
                self.assertTrue(architecture.find_qualification_runner_dependency_violations(rows))
        for extra in [dependency("runne-runtime", "*"), dependency("reqwest", "=0.12.28")]:
            rows = packages()
            rows[1]["dependencies"].append(extra)
            self.assertTrue(architecture.find_qualification_runner_dependency_violations(rows))
        rows = packages()
        rows[1]["features"] = {"test-support": []}
        self.assertTrue(architecture.find_qualification_runner_dependency_violations(rows))

    def test_runtime_cannot_import_runner_persistence(self):
        rows = packages() + [{"name": "runne-runtime", "dependencies": [dependency("runne-qualification-runner", "*")]}]
        self.assertTrue(architecture.find_qualification_runner_dependency_violations(rows))

    def test_runner_facts_do_not_expand_desktop_admission_owners(self):
        rows = packages()
        for name in ("runne-desktop", "runne-platform-desktop", "runne-daemon"):
            rows.append({"name": name, "dependencies": [dependency("runne-native-qualification", "*", target='cfg(target_os = "macos")')]})
        rows[1]["dependencies"].append(dependency("runne-native-qualification", "*", ("test-support",), kind="dev"))
        self.assertEqual([], architecture.find_native_qualification_admission_dependency_violations(rows))
        changed = copy.deepcopy(rows)
        changed[1]["dependencies"][0]["features"] = ["test-support"]
        self.assertTrue(architecture.find_native_qualification_admission_dependency_violations(changed))
        changed = copy.deepcopy(rows)
        changed[-1]["dependencies"][0]["target"] = None
        self.assertTrue(architecture.find_native_qualification_admission_dependency_violations(changed))
