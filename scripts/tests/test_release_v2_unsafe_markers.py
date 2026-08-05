"""F-1 regression: fixture verifier rejects expanded unsafe marker denylist."""

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.release_v2.fixtures import SOURCE_DATE_EPOCH


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "scripts/package-release-v2.sh"
VERIFY = ROOT / "scripts/verify-release-v2.sh"

# One live instance per new denylist format introduced by F-1.
_UNSAFE_SAMPLES = (
    "github_pat_11AAAAAAAAAAAAAAAAAAAAAAAA",  # GitHub fine-grained PAT
    "gho_AAAAAAAAAAAAAAAAAAAAAAAA",  # GitHub OAuth access token
    "ghu_AAAAAAAAAAAAAAAAAAAAAAAA",  # GitHub user token
    "ghs_AAAAAAAAAAAAAAAAAAAAAAAA",  # GitHub server token
    "ghr_AAAAAAAAAAAAAAAAAAAAAAAA",  # GitHub refresh token
    "glpat-AAAAAAAAAAAAAAAAAAAAAAAA",  # GitLab personal access token
    "xoxb-1234567890-123456789012-abcdef",  # Slack bot token
    "xoxa-1234567890-123456789012-abcdef",  # Slack app token
    "xoxp-1234567890-123456789012-abcdef",  # Slack user token
    "xoxr-1234567890-123456789012-abcdef",  # Slack refresh token
    "xoxs-1234567890-123456789012-abcdef",  # Slack session token
    "ASIA1234567890ABCDEF",  # AWS STS temporary credential
    "-----BEGIN PRIVATE KEY-----",  # PEM private key header
    "-----BEGIN RSA PRIVATE KEY-----",  # PEM RSA private key header
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJydW5uZS10ZXN0LW9ubHkifQ.not-a-signature",  # JWT
    "Authorization: Bearer abc123",  # Authorization header
    "\\\\server\\share\\fixture",  # UNC path
    "/var/folders/zz/abcdef",  # macOS temporary directory
    "sk-ant-1234567890abcdef1234567890abcdef",  # Anthropic secret key
    "sk-1234567890abcdef1234567890abcdef",  # OpenAI secret key
)


class ReleaseV2UnsafeMarkerTests(unittest.TestCase):
    def test_each_expanded_marker_blocks_fixture_verification(self) -> None:
        for marker in _UNSAFE_SAMPLES:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "fixture"
                self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
                name = "human/changelog.md"
                self._append_marker(output, name, marker)
                before = self._snapshot(output)
                result = self._run(VERIFY, "--candidate", str(output), "--fixture")
                self.assertEqual(result.returncode, 1)
                document = self._report(result)
                self.assertEqual(document["error"]["code"], "PathUnsafe")
                self.assertNotIn("claims", document)
                self.assertEqual(before, self._snapshot(output))

    def test_clean_generated_fixture_remains_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
            result = self._run(VERIFY, "--candidate", str(output), "--fixture")
            self.assertEqual(result.returncode, 0)
            document = self._report(result)
            self.assertEqual(document["fixture_status"], "STRUCTURAL_FIXTURE_VALID")

    def test_short_sk_prefix_is_not_a_false_positive(self) -> None:
        from scripts.release_v2.human_fixture_validation import _UNSAFE_MARKER

        self.assertIsNone(_UNSAFE_MARKER.search("sk-abc"))
        self.assertIsNone(_UNSAFE_MARKER.search("uses sk-12 tokens nowhere"))

    def _append_marker(self, root: Path, name: str, marker: str) -> None:
        target = root / name
        raw = target.read_bytes() + f"\n{marker}\n".encode("utf-8")
        target.write_bytes(raw)
        (root / f"{name}.sha256").write_text(
            f"{hashlib.sha256(raw).hexdigest()}  {name}\n", encoding="utf-8"
        )

    def _snapshot(self, root: Path) -> dict[str, bytes]:
        return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    def _report(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertTrue(result.stdout.endswith("\n"))
        return json.loads(result.stdout)

    def _run(self, executable: Path, *arguments: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(executable), *arguments], cwd=ROOT, check=check, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )


if __name__ == "__main__":
    unittest.main()
