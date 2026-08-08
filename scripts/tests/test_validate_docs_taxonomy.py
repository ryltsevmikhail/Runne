"""Closed-world tests for the RC0 documentation taxonomy framework."""
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PARTS = ROOT / "scripts" / "validate_docs_parts"


def load_module(name, path):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FRONT_MATTER = load_module("front_matter", PARTS / "front_matter.py")
TAXONOMY = load_module("documentation_taxonomy", PARTS / "documentation_taxonomy.inc")


def valid_document(status="ready", extra="", body="safe text\n"):
    return (
        "---\n"
        "title: \"Guide\"\n"
        f"status: \"{status}\"\n"
        "document_type: \"reference\"\n"
        "source_status: \"Decision\"\n"
        "created: 2026-08-08\n"
        "updated: 2026-08-08\n"
        "owners:\n"
        "  - gocode-runtime\n"
        f"{extra}"
        "---\n"
        f"{body}"
    ).encode("utf-8")


class DocumentationTaxonomyTests(unittest.TestCase):
    def assert_code(self, callable_, code):
        with self.assertRaisesRegex(ValueError, rf"^{code}$"):
            callable_()

    def test_rejects_duplicate_yaml_keys(self):
        self.assert_code(
            lambda: FRONT_MATTER.parse_restricted_front_matter(
                b"status: ready\nstatus: review\n"
            ),
            "FM_DUPLICATE_KEY",
        )

    def test_rejects_anchor_tag_and_multidocument_front_matter(self):
        for raw in (b"status: &x ready\n", b"---\nstatus: yes\n---\n---\n"):
            self.assert_code(
                lambda raw=raw: FRONT_MATTER.parse_restricted_front_matter(raw),
                "FM_UNSUPPORTED_YAML",
            )

    def test_rejects_implicit_scalar_coercion(self):
        self.assert_code(
            lambda: FRONT_MATTER.parse_restricted_front_matter(b"status: yes\n"),
            "FM_IMPLICIT_SCALAR",
        )

    def test_accepts_quoted_scalar_punctuation(self):
        parsed = FRONT_MATTER.parse_restricted_front_matter(b'title: "R&D! [v1] {safe}"\n')
        self.assertEqual(parsed["title"], "R&D! [v1] {safe}")

    def test_rejects_coercible_list_scalar(self):
        self.assert_code(
            lambda: FRONT_MATTER.parse_restricted_front_matter(b"owners:\n  - yes\n"),
            "FM_IMPLICIT_SCALAR",
        )

    def test_rejects_invalid_iso_date(self):
        self.assert_code(
            lambda: FRONT_MATTER.parse_restricted_front_matter(b"created: 2026-02-30\n"),
            "FM_INVALID_DATE",
        )

    def test_rejects_unmapped_legacy_and_unexpected_taxonomy_value(self):
        self.assertEqual(
            TAXONOMY.validate_taxonomy_fields({"status": "ready"}), []
        )
        self.assertEqual(
            TAXONOMY.validate_taxonomy_fields({"status": "retired"}),
            ["TAXONOMY_UNMAPPED_STATUS:retired"],
        )
        self.assertEqual(
            TAXONOMY.validate_taxonomy_fields({"document_type": "unknown"}),
            ["TAXONOMY_UNMAPPED_DOCUMENT_TYPE:unknown"],
        )

    def test_applies_restricted_front_matter_before_taxonomy(self):
        with self.fixture_root() as root:
            self.write_manifests(root, [("docs/guide.md", "governed", None),
                                        ("docs/late.md", "governed", None)])
            guide = root / "docs" / "guide.md"
            guide.write_bytes(valid_document(extra='policy: "unexpected"\n'))
            self.assertEqual(
                TAXONOMY.validate_document_universe(root),
                ["DOCUMENT_FRONT_MATTER:docs/guide.md:FM_UNKNOWN_KEY"],
            )
            guide.write_bytes(valid_document(status="retired"))
            self.assertEqual(
                TAXONOMY.validate_document_universe(root),
                ["DOCUMENT_TAXONOMY:docs/guide.md:TAXONOMY_UNMAPPED_STATUS:retired"],
            )

    def test_rejects_omitted_and_extra_universe_path(self):
        with self.fixture_root() as root:
            self.write_manifests(root, [("docs/guide.md", "governed", None),
                                        ("docs/extra.md", "governed", None)])
            self.assertEqual(
                TAXONOMY.validate_document_universe(root),
                ["UNIVERSE_EXTRA_PATH:docs/extra.md", "UNIVERSE_OMITTED_PATH:docs/late.md"],
            )

    def test_rejects_unlisted_claim_inside_governed_in_scope_document(self):
        with self.fixture_root() as root:
            self.write_manifests(root, [("docs/guide.md", "governed", None),
                                        ("docs/late.md", "governed", None)])
            (root / "docs" / "guide.md").write_bytes(valid_document(body="RC0-qualified now.\n"))
            self.assertEqual(
                TAXONOMY.validate_document_universe(root),
                ["CLAIM_UNLISTED:docs/guide.md:RC0_QUALIFIED"],
            )

    def test_rejects_unlisted_claim_inside_non_governed_document(self):
        with self.fixture_root() as root:
            self.write_manifests(root, [("docs/guide.md", "governed", None),
                                        ("docs/late.md", "non_governed", "fixture exception")])
            (root / "docs" / "late.md").write_bytes(valid_document(body="RC0-qualified now.\n"))
            self.assertEqual(
                TAXONOMY.validate_document_universe(root),
                ["CLAIM_UNLISTED:docs/late.md:RC0_QUALIFIED"],
            )

    def test_requires_reason_for_release_directory_exclusion(self):
        with self.fixture_root(extras=("docs/release/notes.md", "docs/desktop/09-release/guide.md",
                                       "docs/desktop/03-desktop/guide.md")) as root:
            self.write_manifests(root, [
                ("docs/guide.md", "governed", None),
                ("docs/late.md", "governed", None),
                ("docs/release/notes.md", "non_governed", ""),
                ("docs/desktop/09-release/guide.md", "governed", None),
                ("docs/desktop/03-desktop/guide.md", "governed", None),
            ])
            self.assertEqual(
                TAXONOMY.validate_document_universe(root),
                ["UNIVERSE_EXCLUSION_REASON:docs/release/notes.md"],
            )

    def test_rejects_unicode_case_and_line_wrap_claim_variants(self):
        with self.fixture_root() as root:
            self.write_manifests(root, [("docs/guide.md", "governed", None),
                                        ("docs/late.md", "governed", None)])
            (root / "docs" / "guide.md").write_bytes(
                valid_document(body=(
                    "ＲＣ０_QUALI\nFIED now. Candidate PASS. Production qualification PASS. "
                    "Release PASS. Signing PASS. Notarization PASS. Publication PASS.\n"
                ))
            )
            self.assertEqual(
                TAXONOMY.validate_document_universe(root),
                [
                    "CLAIM_UNLISTED:docs/guide.md:CANDIDATE_PASS",
                    "CLAIM_UNLISTED:docs/guide.md:NOTARIZATION_PASS",
                    "CLAIM_UNLISTED:docs/guide.md:PRODUCTION_QUALIFICATION",
                    "CLAIM_UNLISTED:docs/guide.md:PUBLICATION_PASS",
                    "CLAIM_UNLISTED:docs/guide.md:RC0_QUALIFIED",
                    "CLAIM_UNLISTED:docs/guide.md:RELEASE_PASS",
                    "CLAIM_UNLISTED:docs/guide.md:SIGNING_PASS",
                ],
            )

    def test_rejects_invalid_utf8_tracked_path(self):
        with self.fixture_root() as root:
            bad = os.fsencode(root) + b"/docs/bad-\xff.md"
            descriptor = os.open(bad, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(descriptor)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assert_code(lambda: TAXONOMY.tracked_markdown_paths(root), "UNIVERSE_INVALID_UTF8_PATH")

    def fixture_root(self, extras=()):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "docs" / "rc0").mkdir(parents=True)
        (root / "docs" / "guide.md").write_bytes(valid_document())
        (root / "docs" / "late.md").write_bytes(valid_document())
        design = root / "docs" / "superpowers" / "specs" / "2026-08-08-rc0-candidate-design.md"
        design.parent.mkdir(parents=True)
        design.write_bytes(valid_document(body="RC0-candidate design policy is non-production.\n"))
        for extra in extras:
            path = root / extra
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(valid_document())
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        return directory_context(root)

    def write_manifests(self, root, entries):
        entries = list(entries) + [
            ("docs/superpowers/specs/2026-08-08-rc0-candidate-design.md", "governed", None)
        ]
        governed = [path for path, state, _ in entries if state == "governed"]
        inventory = []
        for path, state, reason in entries:
            record = {"path": path, "classification": state}
            if reason is not None:
                record["reason"] = reason
            inventory.append(record)
        rc0 = root / "docs" / "rc0"
        (rc0 / "document-universe-v1.json").write_text(json.dumps({"paths": inventory}), encoding="utf-8")
        (rc0 / "governed-scope-v1.json").write_text(json.dumps({"paths": governed}), encoding="utf-8")
        (rc0 / "status-claims-v1.json").write_text(
            json.dumps({"claims": [TAXONOMY.REQUIRED_CLAIM]}), encoding="utf-8"
        )
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)


class directory_context:
    def __init__(self, root):
        self.root = root

    def __enter__(self):
        return self.root

    def __exit__(self, *_):
        return False


if __name__ == "__main__":
    unittest.main()
