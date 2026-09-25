"""Profile hard-cut documentation must not relabel historical evidence."""

import tempfile
import unittest
from pathlib import Path

from scripts.desktop.capability_manifest_impl.validation import (
    validate_documented_profile_provenance,
)


CURRENT_HASH = "4a97008ecd35edd2022816844fc931e893e29835c0bb9e4d8d8cdab70c9259d4"
PREVIOUS_HASH = "f9744ae62f1245480122dfd73560e49532f2313cc9ce1360ac10987d7318b3dd"
OLD_HASH = "bc9b2d46b617ae1ef7c0bfad6b5ce8655779d5299822421d999b3f2a0b181429"
RUNTIME = "6311992cea0551dab406a93b855ce2c49507e07e"


class DesktopProfileProvenanceTests(unittest.TestCase):
    def fixture(self, root: Path) -> dict[str, Path]:
        paths = {
            "OQ": root / "docs/desktop/decisions/OPEN_QUESTIONS.md",
            "CONTRACT": root / "docs/desktop/05-runtime-integration/CLIENT_RUNTIME_CONTRACT.md",
            "MATRIX": root / "docs/desktop/05-runtime-integration/COMPATIBILITY_MATRIX.md",
        }
        for path in paths.values():
            path.parent.mkdir(parents=True, exist_ok=True)
        historical = f"gocode-ui-client/1 {RUNTIME} {OLD_HASH}"
        previous = f"Previous Task 8D contract gocode-ui-client/2 {PREVIOUS_HASH}"
        current = f"Current source tree gocode-ui-client/3 {CURRENT_HASH}"
        paths["OQ"].write_text(
            f"OQ-009 {historical}\n{previous}\n{current}\n", encoding="utf-8"
        )
        paths["CONTRACT"].write_text(
            f"{historical}\n{previous}\n{current}\n", encoding="utf-8"
        )
        paths["MATRIX"].write_text(
            f"| UI Phase 0 | {historical} |\n{previous}\n{current}\n", encoding="utf-8"
        )
        return paths

    def test_accepts_distinct_historical_and_current_tuples(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            self.assertEqual(validate_documented_profile_provenance(root, CURRENT_HASH), ())

    def test_rejects_partial_historical_relabel_and_current_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self.fixture(root)
            paths["OQ"].write_text(
                paths["OQ"].read_text(encoding="utf-8").replace(
                    "gocode-ui-client/1", "gocode-ui-client/2", 1
                ),
                encoding="utf-8",
            )
            paths["MATRIX"].write_text(
                paths["MATRIX"].read_text(encoding="utf-8").replace(CURRENT_HASH, "0" * 64),
                encoding="utf-8",
            )
            errors = validate_documented_profile_provenance(root, CURRENT_HASH)
            self.assertIn("PROFILE_PROVENANCE_HISTORICAL:OQ", errors)
            self.assertIn("PROFILE_PROVENANCE_CURRENT:MATRIX", errors)

    def test_rejects_previous_profile_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self.fixture(root)
            paths["MATRIX"].write_text(
                paths["MATRIX"]
                .read_text(encoding="utf-8")
                .replace(PREVIOUS_HASH, "0" * 64),
                encoding="utf-8",
            )
            errors = validate_documented_profile_provenance(root, CURRENT_HASH)
            self.assertIn("PROFILE_PROVENANCE_V2:MATRIX", errors)


if __name__ == "__main__":
    unittest.main()
