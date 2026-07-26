import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).parents[1] / "validate_architecture.py"
SPEC = importlib.util.spec_from_file_location("validate_architecture", MODULE_PATH)
architecture = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(architecture)


class RustDependencyRulesTest(unittest.TestCase):
    def test_allows_documented_dependency_direction(self):
        violations = architecture.find_rust_dependency_violations(
            {
                "gocode-desktop": {"gocode-app-core", "gocode-platform-desktop"},
                "gocode-app-core": {"gocode-runtime-client", "gocode-local-store"},
                "gocode-platform-desktop": {"gocode-platform-ports"},
            }
        )

        self.assertEqual([], violations)

    def test_rejects_platform_implementation_importing_app_core(self):
        violations = architecture.find_rust_dependency_violations(
            {"gocode-platform-desktop": {"gocode-app-core"}}
        )

        self.assertEqual(
            ["gocode-platform-desktop -> gocode-app-core is forbidden"],
            violations,
        )


if __name__ == "__main__":
    unittest.main()
