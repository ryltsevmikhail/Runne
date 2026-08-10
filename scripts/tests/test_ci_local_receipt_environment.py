import copy
import dataclasses
import importlib
import os
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.tests import test_ci_local_receipt_security as security_tests


class LocalInputReceiptEnvironmentTests(unittest.TestCase):
    def test_executable_replacement_between_pre_and_post_state_blocks_receipt(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        state_module = importlib.import_module("scripts.ci_local_receipt_state")
        runtime = state_module.resolve_trusted_runtime()
        changed_executables = copy.deepcopy(runtime.executables)
        changed_executables["bash"]["sha256"] = "0" * 64
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
            + "rustup --version >/dev/null 2>&1\n"
            + "pnpm --version >/dev/null\n"
            + f"printf 'run\\n' >> {shlex.quote(os.fspath(marker))}\n"
        )


if __name__ == "__main__":
    unittest.main()
