import tempfile
import unittest
from pathlib import Path

from scripts.validate_visual_fixtures import validate_registry


class VisualFixtureRegistryTest(unittest.TestCase):
    def test_rejects_a_missing_donor_golden_in_release_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = root / "fixtures.yaml"
            registry.write_text(
                """
donor:
  commit: abcdef1234567890
fixtures:
  - { id: desk-projects-default, donor_path: /, state_data: projects.empty, golden_key: "abcdef1/macos-webkit/projects@1x" }
""",
                encoding="utf-8",
            )

            errors = validate_registry(registry, root / "goldens", require_goldens=True)

            self.assertEqual(
                errors,
                ["desk-projects-default: missing approved donor golden abcdef1/macos-webkit/projects@1x.png"],
            )

    def test_accepts_an_approved_golden_with_matching_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = root / "fixtures.yaml"
            registry.write_text(
                """
donor:
  commit: abcdef1234567890
fixtures:
  - { id: desk-projects-default, donor_path: /, state_data: projects.empty, golden_key: "abcdef1/macos-webkit/projects@1x" }
""",
                encoding="utf-8",
            )
            golden = root / "goldens/abcdef1/macos-webkit/projects@1x.png"
            golden.parent.mkdir(parents=True)
            golden.write_bytes(b"png")
            golden.with_suffix(".png.provenance.json").write_text(
                '{"fixture_id":"desk-projects-default","donor_commit":"abcdef1234567890","approved":true}',
                encoding="utf-8",
            )

            self.assertEqual(
                validate_registry(registry, root / "goldens", require_goldens=True),
                [],
            )


if __name__ == "__main__":
    unittest.main()
