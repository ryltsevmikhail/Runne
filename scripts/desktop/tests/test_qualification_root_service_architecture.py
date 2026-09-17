import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("root_service_architecture", Path(__file__).parents[1] / "validate_architecture.py")
architecture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(architecture)


def package():
    normal = {name: ("*", []) for name in architecture.ROOT_SERVICE_INTERNAL}
    normal.update({"base64": ("=0.22.1", []), "ed25519-dalek": ("=2.1.1", []),
                   "hex": ("^0.4", []), "rand": ("=0.8.7", []),
                   "serde": ("=1.0.229", ["derive"]), "serde_json": ("=1.0.151", []),
                   "sha2": ("=0.10.8", []), "zeroize": ("=1.9.0", []),
                   "rustix": ("=1.1.4", ["fs", "process"])})
    return {"name": architecture.ROOT_SERVICE_PACKAGE, "features": {},
            "manifest_path": "/repo/crates/runne-qualification-root-service/Cargo.toml",
            "targets": [{"kind": ["bin"], "src_path": "/repo/crates/runne-qualification-root-service/src/main.rs"}],
            "dependencies": [{"name": name, "req": req, "features": features, "kind": None,
                              "source": None if name.startswith("runne-") else architecture.CARGO_REGISTRY_SOURCE,
                              "path": f"/repo/crates/{name}" if name.startswith("runne-") else None,
                              "target": 'cfg(target_os = "macos")' if name in {"rustix", "runne-macos-file-security"} else None}
                             for name, (req, features) in normal.items()]}


class RootServiceArchitectureTests(unittest.TestCase):
    def check(self, rows):
        return architecture.find_qualification_root_service_violations(rows, Path("/repo"))

    def test_only_fixed_binary_and_reviewed_dependencies(self):
        self.assertEqual([], self.check([package()]))
        self.assertTrue(self.check([]))
        self.assertTrue(self.check([package(), package()]))

    def test_library_import_and_runtime_key_injection_edges_reject(self):
        row = package()
        row["targets"][0]["kind"] = ["lib"]
        self.assertTrue(self.check([row]))
        row = package()
        self.assertTrue(self.check([row, {"name": "runne-desktop", "dependencies": [{"name": row["name"]}]}]))
        row["features"] = {"test-support": []}
        self.assertTrue(self.check([row]))
        for update in ({"features": ["test-support"]}, {"path": "/other/api"}, {"kind": "build"}, {"optional": True}):
            row = package()
            row["dependencies"][0].update(update)
            self.assertTrue(self.check([row]))
        row = package()
        bad = copy.deepcopy(row)
        bad["dependencies"].append({"name": "runne-runtime"})
        self.assertTrue(self.check([bad]))


if __name__ == "__main__":
    unittest.main()
