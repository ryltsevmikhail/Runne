"""Tests for path-filtered scoped local CI selection (ci_local_scope)."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import ci_local_scope as scope


class ClassifyTests(unittest.TestCase):
    def test_runtime_paths(self) -> None:
        paths = (
            "crates/gocode-x/src/lib.rs",
            "Cargo.toml",
            "Cargo.lock",
            "ci/runtime/toolchains.json",
            "rust-toolchain.toml",
            "scripts/verify-phase6-core-closure.sh",
            "scripts/ci.sh",
            "scripts/check-deps.py",
            "scripts/check-source-file-length.py",
        )
        for path in paths:
            self.assertIn("runtime", scope.classify(path), path)

    def test_frontend_paths(self) -> None:
        paths = (
            "apps/desktop/src/App.vue",
            "apps/site/src/x.ts",
            "packages/product/src/x.ts",
            "contracts/gocode-ui-client-1/package.json",
            "tests/desktop/e2e/replay-resume.spec.ts",
            "playwright.config.ts",
            "pnpm-workspace.yaml",
            "package.json",
            "pnpm-lock.yaml",
            "eslint.config.mjs",
            "tsconfig.base.json",
            "scripts/desktop/validate_architecture.py",
        )
        for path in paths:
            self.assertIn("frontend", scope.classify(path), path)

    def test_docs_paths(self) -> None:
        paths = (
            "docs/adr/ADR-0031.md",
            "docs/desktop/STATUS.md",
            "AGENTS.md",
            "README.md",
            "CONTRIBUTING.md",
        )
        for path in paths:
            self.assertIn("docs", scope.classify(path), path)

    def test_docs_profiles_are_also_runtime(self) -> None:
        scopes = scope.classify("docs/profiles/opencode-baseline-inventory-v1.json")
        self.assertEqual(scopes, {"runtime", "docs"})
        scopes = scope.classify("docs/schemas/opencode-baseline-inventory-v1.schema.json")
        self.assertEqual(scopes, {"runtime", "docs"})

    def test_full_fallback_paths(self) -> None:
        paths = (
            "upstream/opencode/src/x.ts",
            ".github/workflows.disabled/ci.yml",
            "ci/other/x",
            "tests/unknown/x",
            "scripts/rc0_policy/activation.py",
            "scripts/ci-local-inputs.sh",
            "scripts/ci-local-scoped.sh",
            "scripts/ci_local_scope.py",
            "scripts/tests/test_ci_local_scope.py",
            "outputs/x.dmg",
            "x/y/z",
            "unknown",
        )
        for path in paths:
            self.assertEqual(scope.classify(path), {"full"}, path)


class GateSelectionTests(unittest.TestCase):
    def test_runtime_only(self) -> None:
        self.assertEqual(
            scope.select_gates({"runtime"}),
            ["local-structural", "containment", "runtime-pinned", "runtime-msrv", "architecture"],
        )

    def test_frontend_only(self) -> None:
        self.assertEqual(scope.select_gates({"frontend"}), ["local-structural", "frontend"])

    def test_docs_only(self) -> None:
        self.assertEqual(scope.select_gates({"docs"}), ["local-structural", "docs"])

    def test_runtime_and_frontend(self) -> None:
        self.assertEqual(
            scope.select_gates({"runtime", "frontend"}),
            ["local-structural", "containment", "runtime-pinned", "runtime-msrv", "frontend"],
        )

    def test_full_selects_every_gate(self) -> None:
        self.assertEqual(scope.select_gates({"full"}), list(scope.ALL_GATES))

    def test_unknown_scope_is_treated_as_full(self) -> None:
        self.assertEqual(scope.select_gates({"runtime", "bogus"}), list(scope.ALL_GATES))


class ChangedFilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.git = Path("git")
        self._run("init", "-q")
        self._run("config", "user.email", "test@example.com")
        self._run("config", "user.name", "Test")
        self._run("commit", "--allow-empty", "-qm", "base")
        self.base = self._run("rev-parse", "HEAD").strip()
        (self.root / "tracked.txt").write_text("one\n", encoding="utf-8")
        (self.root / "modified.txt").write_text("a\n", encoding="utf-8")
        self._run("add", "tracked.txt", "modified.txt")
        self._run("commit", "-qm", "work")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self, *arguments: str) -> str:
        completed = subprocess.run(
            (self.git, *arguments), cwd=self.root,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout

    def test_committed_and_worktree_changes_are_united(self) -> None:
        (self.root / "modified.txt").write_text("b\n", encoding="utf-8")
        (self.root / "new.txt").write_text("x\n", encoding="utf-8")
        changed = scope.changed_files(self.root, self.git, self.base)
        self.assertEqual(
            changed, ["modified.txt", "new.txt", "tracked.txt"]
        )

    def test_worktree_only_changes(self) -> None:
        (self.root / "modified.txt").write_text("b\n", encoding="utf-8")
        changed = scope.changed_files(self.root, self.git, None)
        self.assertEqual(changed, ["modified.txt"])

    def test_bad_base_raises(self) -> None:
        with self.assertRaises(scope.LocalInputReceiptError):
            scope.changed_files(self.root, self.git, "does-not-exist")

    def test_resolve_base_without_remote_returns_none(self) -> None:
        self.assertIsNone(scope.resolve_base(self.root, self.git, None))

    def test_resolve_base_explicit_wins(self) -> None:
        self.assertEqual(scope.resolve_base(self.root, self.git, "HEAD~1"), "HEAD~1")

    def test_plan_unclassified_paths_fall_back_to_full(self) -> None:
        files, scopes, gates = scope.plan(self.root, self.git, self.base)
        self.assertEqual(files, ["modified.txt", "tracked.txt"])
        self.assertEqual(scopes, {"full"})  # unknown paths fall back to full
        self.assertEqual(gates, list(scope.ALL_GATES))

    def test_staged_rename_reports_new_path(self) -> None:
        self._run("mv", "modified.txt", "renamed.txt")
        changed = scope.changed_files(self.root, self.git, None)
        self.assertEqual(changed, ["renamed.txt"])


if __name__ == "__main__":
    unittest.main()
