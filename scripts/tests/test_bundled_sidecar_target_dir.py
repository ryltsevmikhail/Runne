"""Executable target-directory isolation tests for bundled Tauri sidecars."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-gnu"


class BundledSidecarTargetDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "repository"
        scripts = self.root / "scripts" / "desktop"
        scripts.mkdir(parents=True)
        for name in ("stage_bundled_daemon.mjs", "stage_bundled_cli.mjs"):
            shutil.copy2(ROOT / "scripts" / "desktop" / name, scripts)
        self.bin_directory = self.root / "bin"
        self.bin_directory.mkdir()
        (self.bin_directory / "cargo").write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "binary=\n"
            "target=\n"
            "while [ $# -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --bin) binary=$2; shift 2;;\n"
            "    --target) target=$2; shift 2;;\n"
            "    *) shift;;\n"
            "  esac\n"
            "done\n"
            "path=\"${CARGO_TARGET_DIR:?}/$target/release/$binary\"\n"
            "mkdir -p \"$(dirname \"$path\")\"\n"
            "printf fixture > \"$path\"\n"
            "printf '%s\\n' \"$CARGO_TARGET_DIR\" >> \"${FAKE_CARGO_LOG:?}\"\n",
            encoding="utf-8",
        )
        (self.bin_directory / "cargo").chmod(0o755)

    def test_sidecar_cargo_target_directory_is_root_relative_or_absolute(self) -> None:
        for configured, base in (
            ("nested-target", (self.root / "nested-target").resolve()),
            (str((self.root / "absolute-target").resolve()), (self.root / "absolute-target").resolve()),
        ):
            with self.subTest(configured=configured):
                cargo_log = self.root / "cargo.log"
                cargo_log.unlink(missing_ok=True)
                environment = os.environ | {
                    "PATH": f"{self.bin_directory}{os.pathsep}{os.environ['PATH']}",
                    "CARGO_BUILD_TARGET": TARGET,
                    "CARGO_TARGET_DIR": configured,
                    "FAKE_CARGO_LOG": str(cargo_log),
                }
                for script in ("stage_bundled_daemon.mjs", "stage_bundled_cli.mjs"):
                    result = subprocess.run(
                        ["node", str(self.root / "scripts" / "desktop" / script)],
                        cwd=self.root.parent,
                        env=environment,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    cargo_log.read_text(encoding="utf-8").splitlines(),
                    [str(base / "sidecars" / "runned"), str(base / "sidecars" / "runne")],
                )


if __name__ == "__main__":
    unittest.main()
