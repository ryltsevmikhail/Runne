"""Negative coverage for the closed per-registry ADR identity guard."""
from pathlib import Path
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/validate_docs_parts/adr_identity.inc"


def module():
    value = types.ModuleType("adr_identity")
    exec(SOURCE.read_text(encoding="utf-8"), value.__dict__)
    return value


class AdrIdentityTests(unittest.TestCase):
    def registry(self, files):
        directory = tempfile.TemporaryDirectory(dir="/srv/data")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return root

    def valid(self):
        document = '---\ntitle: "ADR-0001: One"\n---\n# ADR-0001: One\n'
        registry = '| [ADR-0001](ADR-0001-one.md) | One | Proposed |\n'
        return {
            "docs/adr/ADR-0001-one.md": document, "docs/adr/README.md": registry,
            "docs/desktop/adr/ADR-0001-one.md": document, "docs/desktop/adr/README.md": registry,
        }

    def test_accepts_independent_runtime_and_desktop_id_spaces(self):
        self.assertEqual(module().validate_adr_identity(self.registry(self.valid())), [])

    def test_rejects_filename_front_matter_heading_and_registry_conflicts(self):
        for path, before, replacement, expected in (
            ("docs/adr/ADR-0001-one.md", 'title: "ADR-0001: One"', 'title: "ADR-0002: One"', "ADR_ID_MISMATCH"),
            ("docs/adr/ADR-0001-one.md", "# ADR-0001: One", "# ADR-0002: One", "ADR_ID_MISMATCH"),
            ("docs/adr/README.md", "[ADR-0001]", "[ADR-0002]", "ADR_REGISTRY_MISMATCH"),
        ):
            files = self.valid()
            files[path] = files[path].replace(before, replacement)
            self.assertTrue(any(expected in item for item in module().validate_adr_identity(self.registry(files))))


if __name__ == "__main__":
    unittest.main()
