import importlib.util
import pathlib
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "verify-test-inventory.py"
SPEC = importlib.util.spec_from_file_location("verify_test_inventory", SCRIPT_PATH)
verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(verifier)


class VerifyTestInventoryTests(unittest.TestCase):
    def test_inventory_contains_required_test(self) -> None:
        self.assertEqual(
            verifier.verify_inventory(
                "containment_unavailable::absent_certificate_is_unavailable: test\n",
                ["containment_unavailable::absent_certificate_is_unavailable"],
            ),
            [],
        )

    def test_empty_inventory_reports_missing_test(self) -> None:
        self.assertIn("missing", verifier.verify_inventory("", ["required::test"])[0])

    def test_duplicate_required_test_is_rejected(self) -> None:
        self.assertIn(
            "duplicate",
            verifier.verify_inventory(
                "required::test: test\n", ["required::test", "required::test"]
            )[0],
        )


if __name__ == "__main__":
    unittest.main()
