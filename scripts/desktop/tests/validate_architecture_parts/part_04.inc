
class SystemPythonCompatibilityTest(unittest.TestCase):
    def test_validator_fragments_load_with_system_python(self):
        system_python = Path("/usr/bin/python3")
        if not system_python.exists():
            self.skipTest("system Python is unavailable")
        result = subprocess.run(
            (
                system_python,
                "-I",
                "-S",
                "-c",
                "import runpy,sys; runpy.run_path(sys.argv[1], run_name='compat')",
                MODULE_PATH,
            ),
            cwd=MODULE_PATH.parents[2],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
