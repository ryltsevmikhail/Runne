"""Regression tests for fail-closed evidence lineage bindings."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).parents[1]))
import pin_lineage as lineage


class PinLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.git("init", "-q", "-b", "current")
        self.write("README", "root\n")
        self.commit("root")
        self.write("apps/base", "base\n")
        self.commit("base")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments], cwd=self.root, check=True, text=True,
            capture_output=True,
        ).stdout.strip()

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def pair(
        self, *, docs_differ: bool = False, inherited_old: bool = False,
    ) -> tuple[str, str, str]:
        self.git("checkout", "-q", "-b", "old")
        self.write("apps/bound", "bound\n")
        if inherited_old:
            self.write("apps/inherited", "old\n")
        if docs_differ:
            self.write("docs/note", "old\n")
        old = self.commit("old binding")
        self.git("checkout", "-q", "current")
        parent = self.git("rev-parse", "HEAD")
        self.write("apps/bound", "bound\n")
        if docs_differ:
            self.write("docs/note", "current\n")
        successor = self.commit("current binding")
        return old, successor, parent

    @staticmethod
    def evidence(field: str, pin: str, successor: str, suffix: str) -> str:
        return (
            "# Evidence\n\n## Evidence manifest\n\n```yaml\n"
            f"{field}: {pin}\n{field}{suffix}: {successor}\n```\n"
        )

    def call(self, evidence: str, field: str, scope: str) -> str:
        previous = Path.cwd()
        os.chdir(self.root)
        try:
            return lineage.require_lineage(evidence, field, scope=scope)
        finally:
            os.chdir(previous)

    def test_code_scope_accepts_only_non_docs_equivalence(self) -> None:
        old, successor, _ = self.pair(docs_differ=True)
        evidence = self.evidence("source_commit", old, successor, "_successor_code")
        self.assertEqual(self.call(evidence, "source_commit", lineage.NON_DOCS), successor)

    def test_full_scope_rejects_a_code_successor(self) -> None:
        old, successor, _ = self.pair()
        evidence = self.evidence("verified_commit", old, successor, "_successor_code")
        with self.assertRaisesRegex(SystemExit, "successor"):
            self.call(evidence, "verified_commit", lineage.FULL)

    def test_external_diff_cannot_spoof_a_mismatched_full_successor(self) -> None:
        old, _, parent = self.pair()
        evidence = self.evidence("verified_commit", old, parent, "_successor")
        with mock.patch.dict(os.environ, {"GIT_EXTERNAL_DIFF": "/bin/true"}):
            with self.assertRaisesRegex(SystemExit, "full-patch identical"):
                self.call(evidence, "verified_commit", lineage.FULL)

    def test_shadow_or_duplicate_manifest_field_fails_closed(self) -> None:
        old, successor, _ = self.pair(docs_differ=True)
        canonical = self.evidence("source_commit", old, "0" * 40, "_successor_code")
        shadow = f"source_commit: {old}\nsource_commit_successor_code: {successor}\n\n{canonical}"
        with self.assertRaisesRegex(SystemExit, "outside canonical"):
            self.call(shadow, "source_commit", lineage.NON_DOCS)
        duplicate = canonical.replace(
            f"source_commit: {old}", f"source_commit: {old}\nsource_commit: {old}",
        )
        with self.assertRaisesRegex(SystemExit, "duplicate"):
            self.call(duplicate, "source_commit", lineage.NON_DOCS)

    def test_non_docs_state_binding_rejects_inherited_divergence(self) -> None:
        old, _, _ = self.pair(inherited_old=True)
        self.git("checkout", "-q", "current")
        self.write("apps/inherited", "diverged\n")
        divergent = self.commit("divergent parent")
        self.write("apps/reverted", "reverted\n")
        successor = self.commit("successor reverts a non-docs change")
        previous = Path.cwd()
        os.chdir(self.root)
        try:
            with self.assertRaisesRegex(SystemExit, "state binding"):
                lineage.require_matching_states(old, successor, (b"apps/inherited",))
        finally:
            os.chdir(previous)
        self.assertNotEqual(divergent, successor)

    def test_merge_base_fatal_exit_is_not_treated_as_non_ancestry(self) -> None:
        result = subprocess.CompletedProcess(["git"], 128, b"", b"fatal: test")
        with mock.patch.object(lineage, "run_git", return_value=result):
            with self.assertRaisesRegex(SystemExit, "merge-base failed"):
                lineage.require_ancestor("0" * 40)


if __name__ == "__main__":
    unittest.main()
