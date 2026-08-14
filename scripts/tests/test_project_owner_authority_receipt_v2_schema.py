"""Closed-contract vectors for the v2 platform-scope authority receipt schema."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy

from scripts.tests.test_project_owner_authority_schemas import ROOT, _errors, _schema_errors


SCHEMA_PATH = ROOT / "docs/schemas/project-owner-authority-receipt-v2.schema.json"


def receipt() -> dict:
    """Return a hand-authored receipt matching the exact v2 public contract."""
    return {
        "schema_version": "gocode.project-owner.authority-receipt/2",
        "repository_id": "gocode",
        "role": "PROJECT_OWNER",
        "purpose": "V1_PLATFORM_SCOPE_AUTHORIZATION",
        "trust_config_sha256": "1" * 64,
        "key_id": "2" * 64,
        "key_epoch": 1,
        "subject": {"object_format": "sha1", "commit_oid": "3" * 40, "tree_oid": "4" * 40},
        "documents": [
            document("docs/adr/ADR-0027-v1-platform-scope.md", "5"),
            document("docs/decisions/v1-platform-scope-v1.json", "6", "gocode.governance.v1-platform-scope-decision/1"),
            document("docs/desktop/adr/ADR-0015-v1-platform-scope.md", "7"),
            document("docs/schemas/v1-platform-scope-decision-v1.schema.json", "8"),
        ],
        "issued_at": "2026-08-13T00:00:00Z",
        "profile": "gocode.project-owner.v1-platform-scope/2",
        "signature": "A" * 86,
    }


def document(path: str, blob: str, schema_id: str | None = None) -> dict:
    """Return one regular sha1 Git blob binding."""
    value = {"path": path, "mode": "100644", "blob_oid": blob * 40, "content_sha256": blob * 64, "byte_length": 1}
    if schema_id is not None:
        value["schema_id"] = schema_id
    return value


class ProjectOwnerAuthorityReceiptV2SchemaTests(unittest.TestCase):
    def test_v2_schema_accepts_only_the_closed_sorted_four_document_profile(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$id"], "gocode.project-owner.authority-receipt/2")
        self.assertFalse(_schema_errors(schema))
        self.assertFalse(_errors(schema, receipt()))

        for mutate in (
            lambda value: value["documents"].pop(2),
            lambda value: value["documents"].reverse(),
            lambda value: value["documents"][1].update(schema_id="gocode.other/1"),
            lambda value: value["documents"][3].update(schema_id="gocode.governance.v1-platform-scope-decision/1"),
            lambda value: value.update(subject={"object_format": "sha256", "commit_oid": "3" * 64, "tree_oid": "4" * 64}),
        ):
            changed = deepcopy(receipt())
            mutate(changed)
            self.assertTrue(_errors(schema, changed))


if __name__ == "__main__":
    unittest.main()
