import importlib.util
import pathlib
import sys
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


if __name__ == "__main__":
    unittest.main()
