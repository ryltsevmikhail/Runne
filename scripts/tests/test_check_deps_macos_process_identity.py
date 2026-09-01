import importlib.util
import pathlib
import sys
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "check-deps.py"
SPEC = importlib.util.spec_from_file_location("check_deps_macos_identity", SCRIPT_PATH)
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


class MacOsProcessIdentityCheckDepsTest(unittest.TestCase):
    def test_dependency_and_architecture_regressions_are_mandatory_ci_inputs(self):
        root = SCRIPT_PATH.parents[1]
        for script in (root / "scripts/ci.sh", root / "scripts/ci-local-inputs.sh"):
            source = script.read_text()
            self.assertIn(
                "scripts.tests.test_check_deps_macos_process_identity", source
            )
            self.assertIn("scripts.desktop.tests.test_validate_architecture", source)

    def test_policy_is_the_exact_low_level_dependency_set(self):
        self.assertEqual(
            checker.POLICIES["runne-macos-process-identity"],
            {
                "core-foundation",
                "libc",
                "nix",
                "runne-api",
                "runne-provider",
                "security-framework",
                "security-framework-sys",
                "sha2",
            },
        )

    def test_exact_checker_rejects_missing_or_extra_edges(self):
        exact = [{
            "name": "runne-macos-process-identity",
            "dependencies": [
                {"name": name, "kind": None}
                for name in checker.POLICIES["runne-macos-process-identity"]
            ],
        }]
        self.assertFalse(checker.macos_process_identity_dependency_errors(exact))
        exact[0]["dependencies"].pop()
        self.assertTrue(checker.macos_process_identity_dependency_errors(exact))
        exact[0]["dependencies"].append({"name": "runne-platform-desktop", "kind": None})
        self.assertTrue(checker.macos_process_identity_dependency_errors(exact))


if __name__ == "__main__":
    unittest.main()
