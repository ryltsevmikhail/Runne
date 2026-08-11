import copy
import contextlib
import dataclasses
import importlib
import os
import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.tests import test_ci_local_receipt_security as security_tests


class LocalInputReceiptEnvironmentTests(unittest.TestCase):
    def test_writable_runtime_directories_cannot_shadow_transitive_commands(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        runtime_module = importlib.import_module("scripts.ci_local_receipt_runtime")
        for command in ("bash", "python3", "git", "grep"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                home, node_bin = self._fake_account_runtime(base)
                fake_marker = base / "fake-ran"
                fake = node_bin / command
                fake.write_text(
                    "#!/usr/bin/bash\n"
                    f"printf fake >> {shlex.quote(os.fspath(fake_marker))}\n"
                    "exit 0\n",
                    encoding="utf-8",
                )
                fake.chmod(0o700)
                repository = base / "repository"
                security_tests.LocalInputReceiptSecurityTests._repository(
                    repository, script=self._transitive_probe_script()
                )
                receipt = security_tests.LocalInputReceiptSecurityTests._receipt_path(
                    base / "receipt"
                )
                with self._patched_account_runtime(runtime_module, home, node_bin):
                    with self.assertRaises(receipt_module.LocalInputReceiptError):
                        receipt_module.run_local_input_gates(repository, receipt)
                self.assertFalse(receipt.exists())

    def test_persistent_cargo_and_git_configuration_cannot_enable_gate(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        runtime_module = importlib.import_module("scripts.ci_local_receipt_runtime")
        cases = {
            "cargo": (
                ".cargo/config.toml",
                '[alias]\nconfigprobe = "!/usr/bin/true"\n',
                "cargo configprobe >/dev/null\n",
            ),
            "git": (
                ".gitconfig",
                '[alias]\nconfigprobe = "status --short"\n',
                "git configprobe >/dev/null\n",
            ),
        }
        for name, (relative, config, command) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                home, node_bin = self._fake_account_runtime(base)
                config_path = home / relative
                config_path.parent.mkdir(parents=True, exist_ok=True)
                config_path.write_text(config, encoding="utf-8")
                repository = base / "repository"
                security_tests.LocalInputReceiptSecurityTests._repository(
                    repository,
                    script="#!/usr/bin/bash\nset -euo pipefail\n" + command,
                )
                receipt = security_tests.LocalInputReceiptSecurityTests._receipt_path(
                    base / "receipt"
                )
                with self._patched_account_runtime(runtime_module, home, node_bin):
                    with self.assertRaises(receipt_module.LocalInputReceiptError):
                        receipt_module.run_local_input_gates(repository, receipt)
                self.assertFalse(receipt.exists())

    def test_executable_replacement_between_pre_and_post_state_blocks_receipt(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        state_module = importlib.import_module("scripts.ci_local_receipt_state")
        runtime = state_module.resolve_trusted_runtime(security_tests.ROOT)
        changed_executables = copy.deepcopy(runtime.executables)
        changed_executables["esbuild"]["sha256"] = "0" * 64
        changed_runtime = dataclasses.replace(
            runtime, executables=changed_executables
        )
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            marker = base / "canonical-ran"
            repository = base / "repository"
            security_tests.LocalInputReceiptSecurityTests._repository(
                repository, script=self._gate_script(marker)
            )
            receipt = security_tests.LocalInputReceiptSecurityTests._receipt_path(
                base / "receipt"
            )
            with mock.patch.object(
                state_module,
                "resolve_trusted_runtime",
                side_effect=(runtime, changed_runtime),
            ):
                with self.assertRaises(receipt_module.LocalInputReceiptError):
                    receipt_module.run_local_input_gates(repository, receipt)
            self.assertEqual(marker.read_text(encoding="utf-8"), "run\n")
            self.assertFalse(receipt.exists())

    def test_hostile_path_cannot_select_gate_or_nested_executables(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        commands = ("bash", "python3", "cargo", "rustup", "pnpm")
        for command in commands:
            with self.subTest(command=command), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                real_marker = base / "canonical-ran"
                fake_marker = base / "fake-ran"
                repository = base / "repository"
                script = self._gate_script(real_marker)
                security_tests.LocalInputReceiptSecurityTests._repository(
                    repository, script=script
                )
                receipt = security_tests.LocalInputReceiptSecurityTests._receipt_path(
                    base / "receipt"
                )
                fake_bin = base / "fake-bin"
                fake_bin.mkdir(mode=0o700)
                fake = fake_bin / command
                fake.write_text(
                    "#!/usr/bin/bash\n"
                    f"printf fake >> {shlex.quote(os.fspath(fake_marker))}\n"
                    "exit 0\n",
                    encoding="utf-8",
                )
                fake.chmod(0o700)
                hostile_path = f"{fake_bin}:{os.environ.get('PATH', '')}"
                with mock.patch.dict(os.environ, {"PATH": hostile_path}):
                    try:
                        receipt_module.run_local_input_gates(repository, receipt)
                    except receipt_module.LocalInputReceiptError as error:
                        self.fail(f"trusted runtime rejected hostile PATH: {error}")
                self.assertTrue(real_marker.exists())
                self.assertEqual(real_marker.read_text(encoding="utf-8"), "run\n")
                self.assertFalse(fake_marker.exists())
                self.assertTrue(receipt.exists())

    def test_hostile_startup_and_loader_environment_is_not_inherited(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        variables = (
            "BASH_ENV",
            "ENV",
            "PYTHONPATH",
            "PYTHONHOME",
            "RUSTC_WRAPPER",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "NODE_OPTIONS",
            "PNPM_HOME",
            "NPM_CONFIG_USERCONFIG",
            "npm_config_userconfig",
            "COREPACK_HOME",
        )
        for variable in variables:
            with self.subTest(variable=variable), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                real_marker = base / "canonical-ran"
                fake_marker = base / "injection-ran"
                payload = base / "payload"
                payload.write_text(
                    f"printf injected >> {shlex.quote(os.fspath(fake_marker))}\nexit 0\n",
                    encoding="utf-8",
                )
                repository = base / "repository"
                script = self._gate_script(
                    real_marker, forbidden=variable, hostile_value=os.fspath(payload)
                )
                security_tests.LocalInputReceiptSecurityTests._repository(
                    repository, script=script
                )
                receipt = security_tests.LocalInputReceiptSecurityTests._receipt_path(
                    base / "receipt"
                )
                with mock.patch.dict(os.environ, {variable: str(payload)}):
                    try:
                        receipt_module.run_local_input_gates(repository, receipt)
                    except receipt_module.LocalInputReceiptError as error:
                        self.fail(f"trusted runtime rejected hostile {variable}: {error}")
                self.assertTrue(real_marker.exists())
                self.assertEqual(real_marker.read_text(encoding="utf-8"), "run\n")
                self.assertFalse(fake_marker.exists())
                self.assertTrue(receipt.exists())

    @staticmethod
    def _gate_script(
        marker: Path,
        forbidden: str | None = None,
        hostile_value: str | None = None,
    ) -> str:
        guard = ""
        if forbidden is not None:
            guard = (
                f'if [[ "${{{forbidden}-}}" == '
                f'{shlex.quote(hostile_value or "")} ]]; then exit 0; fi\n'
            )
        return (
            "#!/usr/bin/bash\n"
            "set -euo pipefail\n"
            + guard
            + "bash -c ':'\n"
            + "python3 -c 'pass'\n"
            + "cargo --version >/dev/null\n"
            + "git --version >/dev/null\n"
            + "grep --version >/dev/null\n"
            + f"printf 'run\\n' >> {shlex.quote(os.fspath(marker))}\n"
        )

    @staticmethod
    def _transitive_probe_script() -> str:
        return (
            "#!/usr/bin/bash\nset -euo pipefail\n"
            "bash -c ':'\n"
            "python3 -c 'pass'\n"
            "git --version >/dev/null\n"
            "grep --version >/dev/null\n"
        )

    @staticmethod
    def _fake_account_runtime(base: Path) -> tuple[Path, Path]:
        home = base / "home"
        cargo_bin = home / ".cargo/bin"
        rustup_home = home / ".rustup"
        node_bin = home / ".nvm/versions/node/v26.5.0/bin"
        for directory in (cargo_bin, rustup_home, node_bin):
            directory.mkdir(parents=True, mode=0o700)
        tools = {
            cargo_bin / "rustup": "echo 'rustup 1.29.0 (fixture 2026-01-01)'\n",
            node_bin / "node": (
                "if [[ ${1-} == --version ]]; then echo v26.5.0; else "
                "exec /usr/bin/bash \"$@\"; fi\n"
            ),
            node_bin / "pnpm": "echo 11.10.0\n",
        }
        for path, body in tools.items():
            path.write_text("#!/usr/bin/bash\n" + body, encoding="utf-8")
            path.chmod(0o700)
        return home, node_bin

    @staticmethod
    def _patched_account_runtime(runtime_module, home: Path, node_bin: Path):
        actual_home = Path.home()
        rust_tools = {
            (version, tool): next(
                actual_home.glob(f".rustup/toolchains/{version}-*/bin/{tool}")
            )
            for version in ("1.97.1", "1.95.0")
            for tool in (
                "rustc", "cargo", "rustdoc", "rustfmt", "cargo-fmt",
                "cargo-clippy", "clippy-driver",
            )
        }

        def rust_tool(_rustup, _rustup_home, version, tool, _environment):
            return rust_tools[(version, tool)]

        return _RuntimePatches(runtime_module, home, node_bin, rust_tool)


class _RuntimePatches:
    def __init__(self, runtime_module, home, node_bin, rust_tool):
        self._stack = contextlib.ExitStack()
        self._patches = (
            mock.patch.object(
                runtime_module.pwd,
                "getpwuid",
                return_value=SimpleNamespace(pw_dir=os.fspath(home)),
            ),
            mock.patch.object(runtime_module, "_rust_tool", side_effect=rust_tool),
            mock.patch.object(
                runtime_module,
                "_node_and_pnpm",
                return_value=(node_bin / "node", node_bin / "pnpm"),
            ),
        )

    def __enter__(self):
        for patcher in self._patches:
            self._stack.enter_context(patcher)
        return self

    def __exit__(self, *exc_info):
        return self._stack.__exit__(*exc_info)


if __name__ == "__main__":
    unittest.main()
