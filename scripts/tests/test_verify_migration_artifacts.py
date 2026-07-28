import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "verify-migration-artifacts.py"
SPEC = importlib.util.spec_from_file_location("verify_migration_artifacts", SCRIPT_PATH)
verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(verifier)


class VerifyMigrationArtifactsTests(unittest.TestCase):
    def setUp(self) -> None:
        verifier.errors.clear()
        verifier.warnings.clear()

    def test_missing_digest_sidecar_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            json_path = pathlib.Path(temporary_directory) / "fixture.json"
            json_path.write_text("{}")

            verifier.verify_digest_sidecar(str(json_path), {})

        self.assertEqual(len(verifier.errors), 1)
        self.assertIn("missing .digest sidecar", verifier.errors[0])

    def test_boolean_is_not_a_json_schema_integer(self) -> None:
        self.assertFalse(verifier.validate_type(True, "integer", "$.count"))
        self.assertEqual(len(verifier.errors), 1)
        self.assertIn("expected integer", verifier.errors[0])

    def test_cli_arguments_override_default_artifact_paths(self) -> None:
        args = verifier.parse_args([
            "--golden-dir", "/tmp/golden",
            "--schema", "/tmp/schema.json",
        ])

        self.assertEqual(args.golden_dir, "/tmp/golden")
        self.assertEqual(args.schema, "/tmp/schema.json")


if __name__ == "__main__":
    unittest.main()
