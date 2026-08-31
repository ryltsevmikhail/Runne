import importlib
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.tests import test_ci_local_receipt_security as fixtures
from scripts.rc0_policy.canonical import canonical_bytes


class LocalInputReceiptGitTests(unittest.TestCase):
    def test_descriptor_path_is_available_on_the_host_platform(self):
        layout_module = importlib.import_module("scripts.rc0_candidate.git_layout")
        with tempfile.TemporaryDirectory() as location:
            directory = Path(location).resolve()
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(layout_module.fd_path(descriptor), directory)
            finally:
                os.close(descriptor)

    def test_lying_fsmonitor_cannot_hide_tracked_byte_mutation(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository = base / "repository"
            fixtures.LocalInputReceiptSecurityTests._repository(
                repository,
                script="#!/bin/sh\nset -eu\nprintf changed > tracked-state\n",
                tracked_state=True,
            )
            helper = repository / ".git/fsmonitor"
            helper.write_text("#!/bin/sh\nprintf 'token\\0'\n", encoding="utf-8")
            helper.chmod(0o700)
            self._git(repository, "config", "core.fsmonitor", str(helper))
            self._git(repository, "update-index", "--fsmonitor")
            self._git(repository, "status", "--porcelain=v1")
            receipt = fixtures.LocalInputReceiptSecurityTests._receipt_path(base / "receipt")
            with self.assertRaises(receipt_module.LocalInputReceiptError):
                receipt_module.run_local_input_gates(repository, receipt)
            self.assertFalse(receipt.exists())

    def test_repository_local_source_controls_fail_closed(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        cases = (
            ("status.showUntrackedFiles", "no"),
            ("diff.ignoreSubmodules", "all"),
            ("submodule.example.ignore", "all"),
            ("core.untrackedCache", "true"),
            ("core.attributesFile", "/dev/null"),
            ("filter.hostile.clean", "!/usr/bin/true"),
            ("include.path", "/dev/null"),
            ("includeIf.gitdir:/tmp/.path", "/dev/null"),
        )
        for key, value in cases:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                repository = base / "repository"
                fixtures.LocalInputReceiptSecurityTests._repository(repository)
                self._git(repository, "config", key, value)
                receipt = fixtures.LocalInputReceiptSecurityTests._receipt_path(base / "receipt")
                with self.assertRaises(receipt_module.LocalInputReceiptError):
                    receipt_module.run_local_input_gates(repository, receipt)
                self.assertFalse(receipt.exists())

    def test_worktree_config_and_redirection_controls_fail_closed(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        cases = (("core.worktree", "/tmp"), ("extensions.worktreeConfig", "true"))
        for key, value in cases:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                repository = base / "repository"
                fixtures.LocalInputReceiptSecurityTests._repository(repository)
                self._git(repository, "config", key, value)
                receipt = fixtures.LocalInputReceiptSecurityTests._receipt_path(base / "receipt")
                with self.assertRaises(receipt_module.LocalInputReceiptError):
                    receipt_module.run_local_input_gates(repository, receipt)
                self.assertFalse(receipt.exists())

    def test_git_config_mutation_during_gate_blocks_receipt(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        scripts = (
            "git config receipt.concurrent-mutation true\n",
            "printf '[status]\\nshowUntrackedFiles = no\\n' > .git/config.worktree\n",
        )
        for script in scripts:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                repository = base / "repository"
                fixtures.LocalInputReceiptSecurityTests._repository(
                    repository, script="#!/bin/sh\nset -eu\n" + script,
                )
                receipt = fixtures.LocalInputReceiptSecurityTests._receipt_path(base / "receipt")
                with self.assertRaises(receipt_module.LocalInputReceiptError):
                    receipt_module.run_local_input_gates(repository, receipt)
                self.assertFalse(receipt.exists())

    def test_canonical_linked_worktree_layout_is_supported(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository, linked = base / "repository", base / "linked"
            fixtures.LocalInputReceiptSecurityTests._repository(repository)
            self._git(repository, "worktree", "add", "-b", "linked-fixture", str(linked))
            receipt = fixtures.LocalInputReceiptSecurityTests._receipt_path(base / "receipt")
            record = receipt_module.run_local_input_gates(linked, receipt)
            self.assertEqual(record["source_revision"], self._git_output(linked, "rev-parse", "HEAD"))
            self.assertTrue(receipt.exists())

    def test_malformed_git_metadata_binding_is_not_consumed(self):
        receipt_module = importlib.import_module("scripts.ci_local_receipt")
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository = base / "repository"
            fixtures.LocalInputReceiptSecurityTests._repository(repository)
            receipt = fixtures.LocalInputReceiptSecurityTests._receipt_path(base / "receipt")
            malformed = copy.deepcopy(receipt_module.run_local_input_gates(repository, receipt))
            malformed["git_metadata_sha256"] = []
            receipt.write_bytes(canonical_bytes(malformed))
            with self.assertRaises(receipt_module.LocalInputReceiptError):
                receipt_module.validate_local_input_receipt(
                    repository, receipt,
                    repository / "scripts/rc0_candidate/inventories/source-candidate-v1.json",
                    consume=True,
                )
            self.assertTrue(receipt.exists())
            self.assertFalse((repository / ".git/gocode-local-input-nonces-v1").exists())

    @staticmethod
    def _git(repository: Path, *arguments: str) -> None:
        subprocess.run(
            ("/usr/bin/git", "-C", repository, *arguments),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @staticmethod
    def _git_output(repository: Path, *arguments: str) -> str:
        return subprocess.run(
            ("/usr/bin/git", "-C", repository, *arguments), check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()


if __name__ == "__main__":
    unittest.main()
