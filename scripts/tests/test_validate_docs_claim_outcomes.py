"""Adversarial outcome grammar tests for the closed Markdown universe."""

from contextlib import nullcontext
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PART = ROOT / "scripts" / "validate_docs_parts" / "documentation_taxonomy.inc"


def load_taxonomy():
    name = "documentation_taxonomy_outcomes"
    spec = importlib.util.spec_from_loader(
        name, SourceFileLoader(name, str(PART))
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TAXONOMY = load_taxonomy()


def document(body: str) -> bytes:
    return (
        "---\n"
        'title: "Claim fixture"\n'
        'status: "ready"\n'
        'document_type: "reference"\n'
        'source_status: "Decision"\n'
        "created: 2026-08-10\n"
        "updated: 2026-08-10\n"
        "owners:\n"
        "  - gocode-runtime\n"
        "---\n"
        f"{body}\n"
    ).encode()


class ClaimOutcomeGrammarTests(unittest.TestCase):
    def fixture(self, *, governed: bool, extra_claim: dict | None = None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        guide = root / "docs" / "guide.md"
        design = root / "docs/superpowers/specs/2026-08-08-rc0-candidate-design.md"
        rc0 = root / "docs" / "rc0"
        guide.parent.mkdir(parents=True)
        design.parent.mkdir(parents=True)
        rc0.mkdir(parents=True)
        guide.write_bytes(document("safe"))
        design.write_bytes(document("RC0-candidate design policy is non-production."))
        records = [
            {"path": "docs/guide.md", "classification": "governed"},
            {
                "path": "docs/superpowers/specs/2026-08-08-rc0-candidate-design.md",
                "classification": "governed",
            },
        ]
        if not governed:
            records[0] = {
                "path": "docs/guide.md",
                "classification": "non_governed",
                "reason": "adversarial fixture",
            }
        claims = [TAXONOMY.REQUIRED_CLAIM]
        if extra_claim is not None:
            claims.append(extra_claim)
        (rc0 / "document-universe-v1.json").write_text(
            json.dumps({"paths": records}), encoding="utf-8"
        )
        governed_paths = [
            item["path"] for item in records if item["classification"] == "governed"
        ]
        (rc0 / "governed-scope-v1.json").write_text(
            json.dumps({"paths": governed_paths}), encoding="utf-8"
        )
        (rc0 / "status-claims-v1.json").write_text(
            json.dumps({"claims": claims}), encoding="utf-8"
        )
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        return nullcontext((root, guide))

    def assert_positive_outcomes(self, body: str, *, governed: bool = True):
        with self.fixture(governed=governed) as (root, guide):
            guide.write_bytes(document(body))
            diagnostics = TAXONOMY.validate_document_universe(root)
        expected = {
            "PRODUCTION_QUALIFICATION",
            "RELEASE_PASS",
            "SIGNING_PASS",
            "NOTARIZATION_PASS",
            "PUBLICATION_PASS",
        }
        for claim_id in expected:
            self.assertIn(f"CLAIM_POSITIVE_OUTCOME:docs/guide.md:{claim_id}", diagnostics)

    def test_natural_success_prose_is_rejected_in_governed_and_non_governed_paths(self):
        prose = (
            "Production qualification is complete. Release approved. Signing succeeded. "
            "Notarization succeeded. Publication authorized."
        )
        self.assert_positive_outcomes(prose, governed=True)
        self.assert_positive_outcomes(prose, governed=False)

    def test_nfkc_case_punctuation_and_line_wrap_variants_are_rejected(self):
        self.assert_positive_outcomes(
            "ＰＲＯＤＵＣＴＩＯＮ—ＱＵＡＬＩＦＩ\nＣＡＴＩＯＮ IS COMPLETE! "
            "rElEaSe:\nAPPROVED! SIGN\nING SUCCEEDED. "
            "Notari-\nzation succeeded; Publication\nAUTHORIZED."
        )

    def test_blocked_manifest_record_cannot_authorize_positive_outcome(self):
        blocked = {
            "claim_id": "PRODUCTION_QUALIFICATION",
            "path": "docs/guide.md",
            "subject": "production qualification",
            "claim_kind": "blocked_status",
            "disposition": "BLOCKED",
            "evidence_binding": "gocode.rc0.evidence-profile/3",
        }
        with self.fixture(governed=True, extra_claim=blocked) as (root, guide):
            guide.write_bytes(document("Production qualification is complete."))
            diagnostics = TAXONOMY.validate_document_universe(root)
        self.assertIn(
            "CLAIM_POSITIVE_OUTCOME:docs/guide.md:PRODUCTION_QUALIFICATION",
            diagnostics,
        )


if __name__ == "__main__":
    unittest.main()
