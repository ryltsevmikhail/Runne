"""Release identity and platform-policy tests for the native package probe."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.desktop.native_package_probe import (
    NON_APPLICABLE_OPERATIONS,
    _command,
    required_native_operations,
)


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-gnu"
TAURI_TARGET = "aarch64-apple-darwin"


class NativePackageProbeReleaseConfigTests(unittest.TestCase):
    def test_probe_uses_tauri_main_binary_and_component_verification(self) -> None:
        mac = " ".join(_command("macos-13-arm64", "executable-identity", "Runne.app"))
        mac_signing = " ".join(_command("macos-13-arm64", "signing-notarization", "Runne.app"))
        linux = " ".join(_command("ubuntu-22.04-x86_64", "executable-identity", "Runne.deb"))
        windows = " ".join(_command("windows-10-22h2-x86_64", "executable-identity", "Runne.exe"))
        self.assertIn("runne-desktop", mac)
        self.assertIn("runned", mac)
        self.assertIn('Contents/MacOS/runne"', mac)
        self.assertIn("runned", mac_signing)
        self.assertIn('Contents/MacOS/runne"', mac_signing)
        self.assertNotIn("--deep", mac_signing)
        self.assertIn("runne-desktop", linux)
        self.assertIn("runne runned", linux)
        self.assertIn('-name "$binary"', linux)
        self.assertIn("test -n", linux)
        self.assertIn("runne-desktop.exe", windows)
        self.assertIn("runne.exe", windows)
        self.assertIn("$componentRoot", windows)
        self.assertIn("Test-Path -PathType Leaf", windows)

    def test_linux_signing_is_explicitly_not_applicable(self) -> None:
        self.assertEqual(NON_APPLICABLE_OPERATIONS["ubuntu-22.04-x86_64"], {"signing-notarization"})
        self.assertNotIn("signing-notarization", required_native_operations("ubuntu-22.04-x86_64"))

    @unittest.skipIf(os.name == "nt", "requires a POSIX shell")
    def test_linux_identity_requires_each_packaged_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {**os.environ, "NATIVE_PROBE_INSTALL_ROOT": str(root)}
            command = _command("ubuntu-22.04-x86_64", "executable-identity", "Runne.deb")
            for name in ("runne-desktop", "runne", "runned"):
                (root / name).write_bytes(name.encode("ascii"))
            self.assertEqual(
                subprocess.run(command, env=environment, capture_output=True).returncode, 0
            )
            for name in ("runne-desktop", "runne", "runned"):
                component = root / name
                component.unlink()
                result = subprocess.run(command, env=environment, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, name)
                component.write_bytes(name.encode("ascii"))

    def test_protected_operations_use_the_installed_desktop_and_owner_boundary(self) -> None:
        for pair in ("macos-13-arm64", "ubuntu-22.04-x86_64"):
            for operation in (
                "protected-launch",
                "protected-relaunch",
                "secure-store-writer-reader",
                "secure-store-third-process-deny",
            ):
                command = " ".join(_command(pair, operation, "Runne.app"))
                with self.subTest(pair=pair, operation=operation):
                    self.assertIn("--bundled-runtime", command)
                    if operation == "secure-store-third-process-deny":
                        self.assertIn("profile.lock", command)
                    self.assertNotIn("PACKAGED_NATIVE_PROBE_SURFACE_NOT_IMPLEMENTED", command)

        windows = " ".join(
            _command("windows-10-22h2-x86_64", "secure-store-third-process-deny", "Runne.exe")
        )
        self.assertIn("Start-ProbeApp", windows)
        self.assertIn("FileShare]::None", windows)


class BundledSidecarStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "repository"
        scripts = self.root / "scripts" / "desktop"
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts" / "desktop" / "stage_bundled_daemon.mjs", scripts)
        self.bin_directory = self.root / "bin"
        self.bin_directory.mkdir()
        (self.bin_directory / "rustc").write_text(
            "#!/bin/sh\nprintf 'host: x86_64-unknown-linux-gnu\\n'\n",
            encoding="utf-8",
        )
        (self.bin_directory / "cargo").write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "target=\n"
            "binary=\n"
            "while [ $# -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --target) target=$2; shift 2;;\n"
            "    --bin) binary=$2; shift 2;;\n"
            "    *) shift;;\n"
            "  esac\n"
            "done\n"
            "[ \"${FAKE_CARGO_MODE:-ok}\" = missing ] && exit 0\n"
            "[ \"${FAKE_CARGO_MODE:-ok}\" = wrong-target ] && target=\n"
            "path=\"${CARGO_TARGET_DIR:?}/${target:+$target/}release/$binary\"\n"
            "mkdir -p \"$(dirname \"$path\")\"\n"
            "printf '%s' \"${FAKE_ARTIFACT_BODY:-fixture}\" > \"$path\"\n"
            "printf '%s %s %s\\n' \"$binary\" \"$target\" \"$CARGO_TARGET_DIR\" >> \"${FAKE_CARGO_LOG:?}\"\n",
            encoding="utf-8",
        )
        for command in ("rustc", "cargo"):
            (self.bin_directory / command).chmod(0o755)

    def _run(
        self,
        script: str,
        body: bytes = b"fixture",
        mode: str = "ok",
        cargo_target: str | None = TARGET,
        tauri_target: str | None = None,
        target: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.bin_directory}{os.pathsep}{environment['PATH']}",
                "CARGO_TARGET_DIR": str(self.root / "target"),
                "FAKE_ARTIFACT_BODY": body.decode("ascii"),
                "FAKE_CARGO_MODE": mode,
                "FAKE_CARGO_LOG": str(self.root / "cargo.log"),
            }
        )
        for name, value in (
            ("CARGO_BUILD_TARGET", cargo_target),
            ("TAURI_ENV_TARGET_TRIPLE", tauri_target),
            ("TARGET", target),
        ):
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        return subprocess.run(
            ["node", str(self.root / "scripts" / "desktop" / script)],
            cwd=self.root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def _copy_cli_script(self) -> None:
        source = ROOT / "scripts" / "desktop" / "stage_bundled_cli.mjs"
        if source.is_file():
            shutil.copy2(source, self.root / "scripts" / "desktop")

    def test_stage_scripts_select_exact_target_and_measure_staged_bytes(self) -> None:
        self._copy_cli_script()
        daemon = self._run("stage_bundled_daemon.mjs", b"daemon-v1")
        writer = self._run("stage_bundled_cli.mjs", b"writer-v1")
        self.assertEqual(daemon.returncode, 0, daemon.stderr)
        self.assertEqual(writer.returncode, 0, writer.stderr)
        binaries = self.root / "apps" / "desktop" / "src-tauri" / "binaries"
        self.assertEqual((binaries / f"runned-{TARGET}").read_bytes(), b"daemon-v1")
        self.assertEqual((binaries / f"runne-{TARGET}").read_bytes(), b"writer-v1")
        for output, binary, contents in (
            (daemon.stdout, "runned", b"daemon-v1"),
            (writer.stdout, "runne", b"writer-v1"),
        ):
            measurement = json.loads(output.splitlines()[-1])
            self.assertEqual(measurement["binary"], binary)
            self.assertEqual(measurement["target"], TARGET)
            self.assertEqual(measurement["bytes"], len(contents))
            self.assertEqual(measurement["sha256"], hashlib.sha256(contents).hexdigest())
        self.assertEqual(
            (self.root / "cargo.log").read_text(encoding="utf-8").splitlines(),
            [
                f"runned {TARGET} {self.root / 'target' / 'sidecars' / 'runned'}",
                f"runne {TARGET} {self.root / 'target' / 'sidecars' / 'runne'}",
            ],
        )

    def test_stage_scripts_reject_missing_or_wrong_target_artifacts(self) -> None:
        self._copy_cli_script()
        for script in ("stage_bundled_daemon.mjs", "stage_bundled_cli.mjs"):
            for mode in ("missing", "wrong-target"):
                with self.subTest(script=script, mode=mode):
                    result = self._run(script, mode=mode)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(f"release artifact was not produced for {TARGET}", result.stderr)

    def test_staging_replaces_modified_artifact_with_its_new_measurement(self) -> None:
        self._copy_cli_script()
        first = self._run("stage_bundled_cli.mjs", b"writer-v1")
        second = self._run("stage_bundled_cli.mjs", b"writer-v2")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        measurement = json.loads(second.stdout.splitlines()[-1])
        self.assertEqual(measurement["sha256"], hashlib.sha256(b"writer-v2").hexdigest())
        self.assertEqual(measurement["bytes"], len(b"writer-v2"))

    def test_stage_scripts_replace_destination_symlinks_instead_of_following_them(self) -> None:
        self._copy_cli_script()
        binaries = self.root / "apps" / "desktop" / "src-tauri" / "binaries"
        binaries.mkdir(parents=True)
        protected = self.root / "protected-artifact"
        protected.write_bytes(b"must-not-change")
        for script, binary in (
            ("stage_bundled_daemon.mjs", "runned"),
            ("stage_bundled_cli.mjs", "runne"),
        ):
            with self.subTest(script=script):
                destination = binaries / f"{binary}-{TARGET}"
                destination.symlink_to(protected)
                result = self._run(script, f"{binary}-v1".encode("ascii"))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(destination.is_symlink())
                self.assertEqual(destination.read_bytes(), f"{binary}-v1".encode("ascii"))
                self.assertEqual(protected.read_bytes(), b"must-not-change")

    def test_stage_scripts_reject_a_symlinked_sidecar_directory(self) -> None:
        self._copy_cli_script()
        sidecar_parent = self.root / "apps" / "desktop" / "src-tauri"
        sidecar_parent.mkdir(parents=True)
        protected = self.root / "protected-sidecars"
        protected.mkdir()
        (sidecar_parent / "binaries").symlink_to(protected, target_is_directory=True)
        for script in ("stage_bundled_daemon.mjs", "stage_bundled_cli.mjs"):
            with self.subTest(script=script):
                result = self._run(script)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("sidecar directory must be a regular directory", result.stderr)
                self.assertEqual(list(protected.iterdir()), [])

    def test_tauri_target_overrides_host_and_leaves_stale_host_sidecars_unselected(self) -> None:
        self._copy_cli_script()
        binaries = self.root / "apps" / "desktop" / "src-tauri" / "binaries"
        binaries.mkdir(parents=True)
        for binary in ("runned", "runne"):
            (binaries / f"{binary}-{TARGET}").write_bytes(b"stale-host")
        daemon = self._run("stage_bundled_daemon.mjs", b"tauri-daemon", cargo_target=None, tauri_target=TAURI_TARGET)
        writer = self._run("stage_bundled_cli.mjs", b"tauri-writer", cargo_target=None, tauri_target=TAURI_TARGET)
        self.assertEqual(daemon.returncode, 0, daemon.stderr)
        self.assertEqual(writer.returncode, 0, writer.stderr)
        staged_daemon = binaries / f"runned-{TAURI_TARGET}"
        staged_writer = binaries / f"runne-{TAURI_TARGET}"
        self.assertTrue(staged_daemon.is_file())
        self.assertTrue(staged_writer.is_file())
        self.assertEqual(staged_daemon.read_bytes(), b"tauri-daemon")
        self.assertEqual(staged_writer.read_bytes(), b"tauri-writer")
        self.assertEqual((binaries / f"runned-{TARGET}").read_bytes(), b"stale-host")
        self.assertEqual((binaries / f"runne-{TARGET}").read_bytes(), b"stale-host")
        self.assertEqual(
            (self.root / "cargo.log").read_text(encoding="utf-8").splitlines(),
            [
                f"runned {TAURI_TARGET} {self.root / 'target' / 'sidecars' / 'runned'}",
                f"runne {TAURI_TARGET} {self.root / 'target' / 'sidecars' / 'runne'}",
            ],
        )

    def test_stage_scripts_reject_conflicting_tauri_and_cargo_targets(self) -> None:
        self._copy_cli_script()
        conflicts = (
            {"tauri_target": TAURI_TARGET},
            {"cargo_target": TARGET, "target": TAURI_TARGET},
        )
        for conflict in conflicts:
            for script in ("stage_bundled_daemon.mjs", "stage_bundled_cli.mjs"):
                with self.subTest(script=script, conflict=conflict):
                    result = self._run(script, **conflict)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("conflicting build targets", result.stderr)
        self.assertFalse((self.root / "cargo.log").exists())

    def test_tauri_config_bundles_writer_resource_and_daemon_sidecar(self) -> None:
        config = json.loads((ROOT / "apps/desktop/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
        package = json.loads((ROOT / "apps/desktop/package.json").read_text(encoding="utf-8"))
        self.assertEqual(config["bundle"]["externalBin"], ["binaries/runned", "binaries/runne"])
        self.assertEqual(
            config["bundle"].get("resources"),
            {"../../../contracts/gocode-ui-client-2/bundle.json": "contracts/gocode-ui-client-2/bundle.json"},
        )
        self.assertIn("stage:bundled-daemon", config["build"]["beforeBuildCommand"])
        self.assertIn("stage:bundled-cli", config["build"]["beforeBuildCommand"])
        self.assertIn("stage:bundled-cli", package["scripts"])


if __name__ == "__main__":
    unittest.main()
