import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).parents[2]
VERIFY = ROOT / "scripts/verify-phase3.sh"
REQUIRED_TESTS = (
    "evidence_fixtures_deterministic",
    "evidence_shadow_import_e2e_sqlite",
    "evidence_direct_store_lineage_stops_at_default_native",
    "evidence_rollback_recovery_e2e",
)


class VerifyPhase3Tests(unittest.TestCase):
    def test_accepts_required_tests_from_included_split_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            script = root / "scripts/verify-phase3.sh"
            script.parent.mkdir()
            shutil.copy2(VERIFY, script)
            source = root / "crates/gocode-store/tests/evidence_phase3.rs"
            parts = source.parent / "evidence_phase3_split_parts"
            parts.mkdir(parents=True)
            source.write_text('include!("evidence_phase3_split_parts/part_01.rs");\n')
            (parts / "part_01.rs").write_text(
                "".join(f"fn {test_name}() {{}}\n" for test_name in REQUIRED_TESTS)
            )
            commands = root / "bin"
            commands.mkdir()
            for command in ("cargo", "python3", "git"):
                stub = commands / command
                stub.write_text("#!/bin/sh\nexit 0\n")
                stub.chmod(0o755)

            result = subprocess.run(
                ["bash", str(script)],
                cwd=root,
                env={**os.environ, "PATH": f"{commands}:{os.environ['PATH']}"},
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
