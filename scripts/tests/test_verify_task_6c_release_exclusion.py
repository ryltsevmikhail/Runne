import importlib.util
import pathlib
import sys
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "verify-task-6c-release-exclusion.py"
SPEC = importlib.util.spec_from_file_location("verify_task_6c_release_exclusion", SCRIPT_PATH)
verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class VerifyTask6CReleaseExclusionTests(unittest.TestCase):
    def test_allowlist_accepts_the_daemon_only_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = pathlib.Path(temporary_directory)
            for relative in verifier.ALLOWLIST:
                path = candidate / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture\n")

            verifier.require_allowlist(candidate)

    def test_allowlist_rejects_each_forbidden_process_artifact(self) -> None:
        for artifact in verifier.FORBIDDEN_ARTIFACTS:
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as temporary_directory:
                candidate = pathlib.Path(temporary_directory)
                for relative in verifier.ALLOWLIST:
                    path = candidate / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"fixture\n")
                (candidate / artifact).write_bytes(b"forbidden\n")

                with self.assertRaisesRegex(SystemExit, "allowlist mismatch"):
                    verifier.require_allowlist(candidate)

    def test_fixture_contains_wrapper_module_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            (root / "scripts").mkdir()

            verifier.copy_release_modules(root)

            self.assertTrue((root / "scripts" / "release_package" / "main.py").is_file())
            self.assertTrue((root / "scripts" / "release_verify" / "verify.py").is_file())


if __name__ == "__main__":
    unittest.main()
