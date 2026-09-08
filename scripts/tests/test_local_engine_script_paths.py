"""Regression tests for Local Engine scripts rooted inside this repository."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-gnu"


class LocalEngineScriptPathsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "repository"
        script_dir = self.root / "scripts" / "local-engine"
        script_dir.mkdir(parents=True)
        for name in (
            "prepare-desktop-sidecars.sh",
            "package-candidate.sh",
            "verify-candidate.py",
            "verify-embedded-source.py",
        ):
            shutil.copy2(ROOT / "scripts" / "local-engine" / name, script_dir)
        engine = self.root / "local-engine"
        (engine / "docs" / "profiles" / "local-engine").mkdir(parents=True)
        (engine / "scripts" / "local-engine").mkdir(parents=True)
        (engine / "Cargo.lock").write_text("snapshot lock\n", encoding="utf-8")
        self.bin_directory = self.root / "bin"
        self.bin_directory.mkdir()
        self._write_stub("rustc", "#!/bin/sh\nprintf 'host: " + TARGET + "\\n'\n")
        self._write_stub(
            "cargo",
            "#!/bin/sh\n"
            "set -eu\n"
            "arguments=$*\n"
            "target=\n"
            "build_target=\n"
            "bins=\n"
            "package=\n"
            "while [ $# -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --target-dir) target=$2; shift 2;;\n"
            "    --target) build_target=$2; shift 2;;\n"
            "    --bin) bins=\"$bins $2\"; shift 2;;\n"
            "    -p) package=$2; shift 2;;\n"
            "    *) shift;;\n"
            "  esac\n"
            "done\n"
            "printf '%s|%s\\n' \"$PWD\" \"$arguments\" >> \"${FAKE_CARGO_LOG:?}\"\n"
            "for binary in $bins; do\n"
            "  mkdir -p \"$target/$build_target/debug\"\n"
            "  printf fixture > \"$target/$build_target/debug/$binary\"\n"
            "done\n"
            "if [ \"$package\" = runne-llama-worker ]; then\n"
            "  mkdir -p \"$target/$build_target/debug\"\n"
            "  printf worker > \"$target/$build_target/debug/runne-llama-worker\"\n"
            "fi\n",
        )
        self._write_stub(
            "python3",
            "#!/bin/sh\nset -eu\n"
            "printf '%s|%s\\n' \"$PWD\" \"$*\" >> \"${FAKE_PYTHON_LOG:?}\"\n"
            "case \"$*\" in *verify-embedded-source.py*) "
            "  test \"${FAKE_PROVENANCE_FAIL:-0}\" = 0 || exit 2;; esac\n",
        )

    def _write_stub(self, name: str, contents: str) -> None:
        path = self.bin_directory / name
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def _run(self, script: str, relative_target: bool = False, fail_provenance: bool = False) -> tuple[subprocess.CompletedProcess[str], Path]:
        target = self.root / "controlled target"
        environment = os.environ | {
            "PATH": f"{self.bin_directory}{os.pathsep}{os.environ['PATH']}",
            "CARGO_TARGET_DIR": target.name if relative_target else str(target),
            "FAKE_CARGO_LOG": str(self.root / "cargo.log"),
            "FAKE_PYTHON_LOG": str(self.root / "python.log"),
            "FAKE_PROVENANCE_FAIL": "1" if fail_provenance else "0",
        }
        outside = self.root.parent / "outside"
        outside.mkdir()
        result = subprocess.run(
            [str(self.root / "scripts" / "local-engine" / script)],
            cwd=outside,
            env=environment,
            capture_output=True,
            text=True,
        )
        return result, target

    def _assert_common_roots(self, target: Path) -> None:
        commands = (self.root / "cargo.log").read_text(encoding="utf-8").splitlines()
        self.assertTrue(commands)
        for command in commands:
            cwd, arguments = command.split("|", 1)
            self.assertIn(cwd, {str(self.root), str(self.root / "local-engine")})
            self.assertIn("--locked", arguments)
            self.assertIn(f"--target-dir {target}", arguments)
            if " build " in f" {arguments} ":
                self.assertIn(f"--target {TARGET}", arguments)
        python_calls = (self.root / "python.log").read_text(encoding="utf-8")
        self.assertIn(str(self.root / "local-engine" / "Cargo.lock"), python_calls)
        self.assertNotIn("runne-local-engine", python_calls)

    def test_package_stops_before_build_when_provenance_fails(self) -> None:
        result, _ = self._run("package-candidate.sh", fail_provenance=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / "cargo.log").exists())

    def _assert_package_roots(self, includes_worker: bool) -> None:
        commands = (self.root / "cargo.log").read_text(encoding="utf-8")
        root_packages = ("runne-daemon", "runne-cli", "runne-daemon-local-engine-effect", "runne-platform-desktop")
        for package in root_packages:
            self.assertIn(f"{self.root}|", next(line for line in commands.splitlines() if f"-p {package}" in line))
        engine_packages = ["runne-provider-local"]
        if includes_worker:
            engine_packages.append("runne-llama-worker")
        for package in engine_packages:
            self.assertIn(f"{self.root / 'local-engine'}|", next(line for line in commands.splitlines() if f"-p {package}" in line))

    def test_prepare_uses_nested_engine_and_the_configured_target_directory(self) -> None:
        result, target = self._run("prepare-desktop-sidecars.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_common_roots(target)
        binaries = self.root / "apps" / "desktop" / "src-tauri" / "binaries"
        self.assertEqual((binaries / f"runned-{TARGET}").read_text(), "fixture")
        self.assertEqual((binaries / f"runne-{TARGET}").read_text(), "fixture")
        self._assert_package_roots(includes_worker=False)
        commands = (self.root / "cargo.log").read_text(encoding="utf-8")
        self.assertIn(f"{self.root}|", commands)
        self.assertIn(f"{self.root / 'local-engine'}|", commands)
        self.assertNotIn("RUNNE_LOCAL_ENGINE_ROOT", (self.root / "scripts" / "local-engine" / "prepare-desktop-sidecars.sh").read_text())

    def test_package_uses_nested_engine_and_the_configured_target_directory(self) -> None:
        result, target = self._run("package-candidate.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_common_roots(target)
        binaries = self.root / "dist" / "local-engine-candidate" / "binaries"
        self.assertEqual((binaries / f"runned-{TARGET}").read_text(), "fixture")
        self.assertEqual((binaries / f"runne-{TARGET}").read_text(), "fixture")
        self.assertEqual((binaries / f"runne-llama-worker-{TARGET}").read_text(), "worker")
        self._assert_package_roots(includes_worker=True)
        self.assertNotIn("RUNNE_LOCAL_ENGINE_ROOT", (self.root / "scripts" / "local-engine" / "package-candidate.sh").read_text())

    def test_package_replaces_a_preexisting_candidate(self) -> None:
        stale = self.root / "dist" / "local-engine-candidate" / "binaries" / "stale-helper"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale", encoding="utf-8")

        result, _ = self._run("package-candidate.sh")

        self.assertEqual(result.returncode, 0, result.stderr)
        binaries = self.root / "dist" / "local-engine-candidate" / "binaries"
        self.assertEqual(
            {entry.name for entry in binaries.iterdir()},
            {
                f"runned-{TARGET}",
                f"runne-{TARGET}",
                f"runne-llama-worker-{TARGET}",
            },
        )

    def test_prepare_resolves_a_relative_target_directory_from_the_repository(self) -> None:
        result, target = self._run("prepare-desktop-sidecars.sh", relative_target=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_common_roots(target)


if __name__ == "__main__":
    unittest.main()
