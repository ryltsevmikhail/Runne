import importlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.tests import test_ci_local_receipt_security as security_tests


class LocalInputReceiptNamespaceTests(unittest.TestCase):
    def test_docs_gate_runs_both_canonical_validators_in_closed_namespace(self):
        namespace_module = importlib.import_module("scripts.ci_local_receipt_namespace")
        runtime_module = importlib.import_module("scripts.ci_local_receipt_runtime")
        runtime = runtime_module.resolve_trusted_runtime(security_tests.ROOT)
        with namespace_module.execution_namespace(runtime) as namespace:
            completed = subprocess.run(
                [os.fspath(namespace.bash), "scripts/ci-local-docs.sh"],
                cwd=security_tests.ROOT,
                env=namespace.environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        gate = (security_tests.ROOT / "scripts/ci-local-inputs.sh").read_text(
            encoding="utf-8"
        )
        self.assertEqual(gate.count('"$trusted_bash" scripts/ci-local-docs.sh'), 2)
        self.assertNotIn("validate_markdown_links.py", gate)

    def test_closed_path_excludes_account_tool_directories_and_binds_frontend(self):
        namespace_module = importlib.import_module("scripts.ci_local_receipt_namespace")
        runtime_module = importlib.import_module("scripts.ci_local_receipt_runtime")
        runtime = runtime_module.resolve_trusted_runtime(security_tests.ROOT)
        with namespace_module.execution_namespace(runtime) as namespace:
            environment = namespace.environment
            components = environment["PATH"].split(os.pathsep)
            self.assertEqual(components[-1], "/usr/bin")
            self.assertNotIn(os.fspath(runtime.account_home / ".cargo/bin"), components)
            self.assertNotIn(os.fspath(runtime.base_commands["node"].parent), components)
            for commands in runtime.rust_commands.values():
                self.assertNotIn(os.fspath(commands["cargo"].parent), components)
            for name, target in runtime.frontend.items():
                self.assertEqual(
                    environment[f"GOCODE_FRONTEND_{name.upper()}"], os.fspath(target)
                )
                self.assertEqual(runtime.executables[name]["path"], os.fspath(target))
            self.assertNotEqual(environment["HOME"], os.fspath(runtime.account_home))
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertEqual(environment["NPM_CONFIG_USERCONFIG"], "/dev/null")

    def test_unexpected_namespace_write_blocks_receipt_and_preserves_state(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository = base / "repository"
            security_tests.LocalInputReceiptSecurityTests._repository(
                repository,
                script=(
                    "#!/usr/bin/bash\nset -euo pipefail\n"
                    "printf unexpected > \"$HOME/unexpected\"\n"
                ),
            )
            receipt = security_tests.LocalInputReceiptSecurityTests._receipt_path(
                base / "receipt"
            )
            tmpdir = base / "execution"
            tmpdir.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {"TMPDIR": os.fspath(tmpdir)}):
                with self.assertRaises(receipt_module.LocalInputReceiptError):
                    receipt_module.run_local_input_gates(repository, receipt)
            self.assertFalse(receipt.exists())
            namespaces = list(tmpdir.glob("gocode-local-gate-*"))
            self.assertEqual(len(namespaces), 1)
            self.assertEqual(
                (namespaces[0] / "home/unexpected").read_text(encoding="utf-8"),
                "unexpected",
            )


if __name__ == "__main__":
    unittest.main()
