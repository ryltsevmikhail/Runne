import importlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.tests import test_ci_local_receipt_security as fixtures


class LocalInputReceiptGitlinkTests(unittest.TestCase):
    def setUp(self):
        self.receipt_module = importlib.import_module("scripts.ci_local_receipt")

    def test_absent_or_arbitrary_gitlink_directory_blocks_receipt(self):
        for shape in ("absent", "uninitialized", "arbitrary"):
            with self.subTest(shape=shape), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                if shape == "uninitialized":
                    repository, _child = self._with_submodule(base)
                    self._git(repository, "submodule", "deinit", "-q", "-f", "module")
                else:
                    repository = base / "repository"
                    fixtures.LocalInputReceiptSecurityTests._repository(repository)
                    child = self._child(base / "child")
                    self._git(
                        repository, "update-index", "--add", "--cacheinfo",
                        f"160000,{self._output(child, 'rev-parse', 'HEAD')},module",
                    )
                    self._git(repository, "commit", "-qm", "gitlink")
                if shape == "arbitrary":
                    (repository / "module").mkdir()
                    (repository / "module/arbitrary").write_text("not a repository")
                self._blocks(repository, base)

    def test_mismatched_nested_head_blocks_receipt(self):
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository, _child = self._with_submodule(base)
            self._git(repository / "module", "checkout", "-q", "HEAD^")
            self._blocks(repository, base)

    def test_dirty_nested_tracked_or_untracked_bytes_block_receipt(self):
        for dirty in ("tracked", "assume-unchanged", "untracked"):
            with self.subTest(dirty=dirty), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                repository, _child = self._with_submodule(base)
                target = repository / "module" / ("extra" if dirty == "untracked" else "tracked")
                if dirty == "assume-unchanged":
                    self._git(repository / "module", "update-index", "--assume-unchanged", "tracked")
                target.write_text("dirty", encoding="utf-8")
                self._blocks(repository, base)

    def test_unsafe_nested_local_and_worktree_config_blocks_receipt(self):
        cases = (
            ("core.fsmonitor", "/bin/true"),
            ("include.path", "/dev/null"),
            ("status.showUntrackedFiles", "no"),
            ("extensions.worktreeConfig", "true"),
        )
        for key, value in cases:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                repository, _child = self._with_submodule(base)
                self._git(repository / "module", "config", key, value)
                if key == "extensions.worktreeConfig":
                    self._git(repository / "module", "config", "--worktree", "receipt.test", "true")
                self._blocks(repository, base)

    def test_nested_config_or_layout_mutation_during_gate_blocks_receipt(self):
        scripts = (
            "git -C module config receipt.concurrent true\n",
            "printf 'changed\\n' > module/.git\n",
        )
        for script in scripts:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                repository, _child = self._with_submodule(base, script="#!/bin/sh\nset -eu\n" + script)
                self._blocks(repository, base)

    def test_nested_gitlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            grandchild = self._child(base / "grandchild")
            child = self._child(base / "child")
            self._add_submodule(child, grandchild, "nested")
            repository = base / "repository"
            fixtures.LocalInputReceiptSecurityTests._repository(repository)
            self._add_submodule(repository, child, "module")
            self._blocks(repository, base)

    def test_clean_submodule_in_linked_worktree_is_supported(self):
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository, _child = self._with_submodule(base)
            linked = base / "linked"
            self._git(repository, "worktree", "add", "-q", "-b", "linked-fixture", str(linked))
            self._git(linked, "-c", "protocol.file.allow=always", "submodule", "update", "--init")
            receipt = fixtures.LocalInputReceiptSecurityTests._receipt_path(base / "receipt")
            record = self.receipt_module.run_local_input_gates(linked, receipt)
            self.assertEqual(record["source_revision"], self._output(linked, "rev-parse", "HEAD"))
            self.assertTrue(receipt.exists())

    def test_large_tracked_tree_has_streaming_source_binding(self):
        tree_module = importlib.import_module("scripts.ci_local_receipt_git_tree")
        entries = {
            f"entries/entry-{index:04d}": ("100644", f"{index:040x}")
            for index in range(4_097)
        }
        self.assertEqual(
            tree_module.source_digest(entries),
            "fbf46a26c2b664ab35909c8e67edd0f11fb9b3972a5abf109546e12cb303bd26",
        )

    def _with_submodule(self, base: Path, *, script=None):
        child = self._child(base / "child")
        repository = base / "repository"
        fixtures.LocalInputReceiptSecurityTests._repository(repository, script=script)
        self._add_submodule(repository, child, "module")
        return repository, child

    def _child(self, path: Path) -> Path:
        path.mkdir()
        self._git(path, "init", "-q")
        self._git(path, "config", "user.email", "fixture@example.invalid")
        self._git(path, "config", "user.name", "Fixture")
        for value in ("first", "second"):
            (path / "tracked").write_text(value, encoding="utf-8")
            self._git(path, "add", "tracked")
            self._git(path, "commit", "-qm", value)
        return path

    def _add_submodule(self, repository: Path, child: Path, name: str) -> None:
        self._git(
            repository, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
            str(child), name,
        )
        self._git(repository, "commit", "-qam", f"add {name}")

    def _blocks(self, repository: Path, base: Path) -> None:
        receipt = fixtures.LocalInputReceiptSecurityTests._receipt_path(base / "receipt")
        with self.assertRaises(self.receipt_module.LocalInputReceiptError):
            self.receipt_module.run_local_input_gates(repository, receipt)
        self.assertFalse(receipt.exists())

    @staticmethod
    def _git(repository: Path, *arguments: str) -> None:
        subprocess.run(
            ("/usr/bin/git", "-C", repository, *arguments), check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    @staticmethod
    def _output(repository: Path, *arguments: str) -> str:
        return subprocess.run(
            ("/usr/bin/git", "-C", repository, *arguments), check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()


if __name__ == "__main__":
    unittest.main()
