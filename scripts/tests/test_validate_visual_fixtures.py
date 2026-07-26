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

    def test_accepts_documented_capture_metadata_with_matching_required_provenance(self):
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
                """{
  "fixture_id": "desk-projects-default",
  "donor_commit": "abcdef1234567890",
  "approved": true,
  "captured_at": "2026-07-26T12:00:00.000Z",
  "os": "macOS",
  "webview": "chromium",
  "capture_tool": "gocode-donor-capture",
  "capture_tool_version": "1.0.0",
  "viewport": {"width": 1440, "height": 900},
  "scale": 1,
  "theme": "dark",
  "locale": "en-US",
  "timezone": "UTC",
  "clock": "2026-07-26T12:00:00Z"
}""",
                encoding="utf-8",
            )

            self.assertEqual(
                validate_registry(registry, root / "goldens", require_goldens=True),
                [],
            )

    def test_release_gate_can_validate_one_capture_target_without_weakening_full_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = root / "fixtures.yaml"
            registry.write_text(
                """
donor:
  commit: abcdef1234567890
fixtures:
  - { id: desk-macos, donor_path: /, state_data: projects.empty, capture_target: macos-webkit, golden_key: "abcdef1/macos-webkit/projects@1x" }
  - { id: desk-windows, donor_path: /, state_data: projects.empty, capture_target: windows-webview2, golden_key: "abcdef1/windows-webview2/projects@1x" }
""",
                encoding="utf-8",
            )
            golden = root / "goldens/abcdef1/macos-webkit/projects@1x.png"
            golden.parent.mkdir(parents=True)
            golden.write_bytes(b"png")
            golden.with_suffix(".png.provenance.json").write_text(
                '{"fixture_id":"desk-macos","donor_commit":"abcdef1234567890","approved":true}',
                encoding="utf-8",
            )

            self.assertEqual(
                validate_registry(
                    registry,
                    root / "goldens",
                    require_goldens=True,
                    capture_target="macos-webkit",
                ),
                [],
            )
            self.assertEqual(
                validate_registry(registry, root / "goldens", require_goldens=True),
                ["desk-windows: missing approved donor golden abcdef1/windows-webview2/projects@1x.png"],
            )


if __name__ == "__main__":
    unittest.main()
