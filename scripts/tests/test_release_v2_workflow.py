"""Static safety tests for the isolated structural gate workflow.

Parses ``.github/workflows.disabled/release-structural-gate.yml`` as plain
text with stdlib ``re`` only; no YAML dependency is allowed.  The suite fails
with an explicit reason while the isolated workflow does not exist (RED
phase) and guards every hard requirement of Task 14.

The GitHub-hosted workflows are retained as reference artifacts under
``.github/workflows.disabled/`` after the CI migration to SourceCraft.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_REL = Path(".github/workflows.disabled/release-structural-gate.yml")
WORKFLOW = REPO_ROOT / WORKFLOW_REL
CI_WORKFLOW_REL = ".github/workflows.disabled/ci.yml"
CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"

PROHIBITED_WORDS = ("curl", "deploy", "notary", "publish", "release", "sign", "wget")
PROHIBITED_SUBSTRINGS = (
    "id-token",
    "npm install",
    "pip install",
    "secrets.",
    "setup-node",
    "setup-python",
    "upload-artifact",
)


class ReleaseStructuralWorkflowTests(unittest.TestCase):
    """Read-only text-level assertions over the isolated workflow."""

    def _text(self) -> str:
        if not WORKFLOW.is_file():
            raise AssertionError(
                f"isolated workflow does not exist: {WORKFLOW_REL}"
            )
        return WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_file_exists(self) -> None:
        self.assertTrue(
            WORKFLOW.is_file(),
            f"isolated workflow does not exist: {WORKFLOW_REL}",
        )

    def test_only_manual_dispatch_trigger(self) -> None:
        text = self._text()
        self.assertIn("workflow_dispatch", text)
        for line in text.splitlines():
            stripped = line.strip()
            self.assertFalse(
                re.match(r"^(push|pull_request)\s*:", stripped),
                f"forbidden CI trigger found: {line!r}",
            )

    def test_top_level_permissions_are_read_only(self) -> None:
        text = self._text()
        lines = text.splitlines()
        permissions_indexes = [
            index
            for index, line in enumerate(lines)
            if line.strip() == "permissions:"
        ]
        self.assertEqual(
            len(permissions_indexes),
            1,
            f"exactly one 'permissions:' block is required: {permissions_indexes}",
        )
        permissions_line = lines[permissions_indexes[0]]
        self.assertEqual(
            permissions_line,
            "permissions:",
            f"'permissions:' must be top-level, found: {permissions_line!r}",
        )
        block = []
        for line in lines[permissions_indexes[0] + 1 :]:
            if line and not line.startswith((" ", "\t")):
                break
            if line.strip():
                block.append(line.strip())
        self.assertEqual(
            block,
            ["contents: read"],
            f"permissions block must contain only 'contents: read': {block}",
        )

    def test_checkout_uses_exact_pinned_sha(self) -> None:
        text = self._text()
        self.assertIn(f"actions/checkout@{CHECKOUT_SHA}", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("submodules: false", text)

    def test_both_v2_unittest_modules_are_invoked(self) -> None:
        text = self._text()
        self.assertIn("scripts.tests.test_release_v2_cli", text)
        self.assertIn("scripts.tests.test_release_v2_workflow", text)

    def test_no_prohibited_actions_network_or_secrets(self) -> None:
        text = self._text()
        for word in PROHIBITED_WORDS:
            self.assertNotRegex(
                text,
                rf"\b{re.escape(word)}\b",
                f"prohibited word found: {word}",
            )
        for substring in PROHIBITED_SUBSTRINGS:
            self.assertNotIn(
                substring,
                text,
                f"prohibited pattern found: {substring}",
            )
        self.assertNotIn("docker://", text, "registry action found")
        for line in text.splitlines():
            self.assertFalse(
                re.match(r"^\s*-\s*uses:\s*\S*/setup-[^\s#]*\s*$", line),
                f"setup-* action found: {line!r}",
            )

    def test_ci_yml_is_unchanged(self) -> None:
        result = subprocess.run(
            ["git", "diff", "--exit-code", "--", CI_WORKFLOW_REL],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"ci.yml must remain unchanged:\n{result.stdout}",
        )


if __name__ == "__main__":
    unittest.main()
