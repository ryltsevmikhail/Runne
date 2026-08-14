"""Closed public schema contract for the versioned reconciliation receipt."""

from __future__ import annotations

import json
import hashlib
import unittest
from copy import deepcopy

from scripts.tests.test_project_owner_authority_schemas import ROOT, _errors, _schema_errors
from scripts.project_owner_authority.schema_semantics import reconciliation_receipt_errors


SCHEMA = ROOT / "docs/schemas/project-owner-authority-receipt-v3.schema.json"
PROFILE = ROOT / "scripts/project_owner_authority/fixtures/v3/reconciliation/profile.json"
SUBJECT_S2 = ROOT / "scripts/project_owner_authority/fixtures/v3/reconciliation/subject-s2.json"
EVIDENCE_E2 = ROOT / "scripts/project_owner_authority/fixtures/v3/reconciliation/evidence-e2.json"
INITIAL = ROOT / "scripts/project_owner_authority/fixtures/v3/reconciliation/initial-receipt.json"
TASK13_INITIAL = ROOT / "scripts/project_owner_authority/fixtures/v2/initial-ceremony/receipt-s.json"
RECEIPT_S2 = ROOT / "scripts/project_owner_authority/fixtures/v3/reconciliation/receipt-s2.json"
DOCUMENTS = ROOT / "scripts/project_owner_authority/fixtures/v3/reconciliation/documents"
PATHS = (
    "docs/ROADMAP.md", "docs/STATUS.md", "docs/adr/ADR-0010-sandbox-enforcement.md", "docs/adr/README.md", "docs/decisions/DECISION_LOG.md", "docs/decisions/OPEN_QUESTIONS.md", "docs/desktop/07-testing/CI_AND_PLATFORM_MATRIX.md", "docs/desktop/09-release/PLATFORM_SUPPORT.md", "docs/desktop/ROADMAP.md", "docs/desktop/STATUS.md", "docs/desktop/adr/ADR-0012-platform-support-floor.md", "docs/desktop/adr/README.md", "docs/desktop/decisions/DECISION_LOG.md", "docs/desktop/decisions/OPEN_QUESTIONS.md", "docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md", "docs/matrices/REQUIREMENTS_TRACEABILITY.md", "docs/matrices/v1-platform-scope-claim-migration-v1.json", "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json", "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_MANIFEST_V1.md", "docs/release/COMPATIBILITY_V1.md", "docs/release/POST_RC0_PLATFORM_QUALIFICATION_INTERFACE_V1.md", "docs/release/RELEASE_MANIFEST_V1.md", "docs/superpowers/specs/2026-07-27-phase6-core-native-qualification-design.md", "docs/superpowers/specs/2026-07-27-phase6-security-platform-design.md", "docs/superpowers/specs/2026-07-28-phase10-release-qualification-design.md", "docs/superpowers/specs/2026-07-31-production-capabilities-program-design.md", "docs/superpowers/specs/2026-08-08-rc0-candidate-design.md", "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
)


def receipt() -> dict:
    documents = [{"path": path, "mode": "100644", "blob_oid": "5" * 40, "content_sha256": "6" * 64, "byte_length": 1} for path in PATHS]
    documents[16]["schema_id"] = "gocode.v1-platform-scope-claim-migration/1"
    documents[17]["schema_id"] = "gocode.rc0.post-rc0-platform-composed-universe/1"
    return {"schema_version": "gocode.project-owner.authority-receipt/3", "repository_id": "gocode", "role": "PROJECT_OWNER", "purpose": "POST_RC0_DOCUMENT_RECONCILIATION", "trust_config_sha256": "1" * 64, "key_id": "2" * 64, "key_epoch": 1, "subject": {"object_format": "sha1", "commit_oid": "3" * 40, "tree_oid": "4" * 40}, "documents": documents, "issued_at": "2026-08-13T00:00:01Z", "profile": "gocode.project-owner.post-rc0-document-reconciliation/1", "predecessor_receipt_sha256": "7" * 64, "signature": "A" * 86}


def oid(kind: str, raw: bytes) -> bytes:
    return hashlib.sha1(f"{kind} {len(raw)}\0".encode() + raw).digest()


def tree_oid(files: dict[str, bytes]) -> str:
    tree: dict[str, object] = {}
    for path, raw in files.items():
        node = tree
        *parents, leaf = path.split("/")
        for parent in parents:
            node = node.setdefault(parent, {})  # type: ignore[assignment]
        node[leaf] = raw
    def encode(node: dict[str, object]) -> bytes:
        entries = []
        for name, value in node.items():
            mode, value_oid = ("40000", oid("tree", encode(value))) if isinstance(value, dict) else ("100644", oid("blob", value))
            entries.append((name, mode, value_oid))
        entries.sort(key=lambda item: item[0] + ("/" if item[1] == "40000" else ""))
        return b"".join(f"{mode} ".encode() + name.encode() + b"\0" + value_oid for name, mode, value_oid in entries)
    return oid("tree", encode(tree)).hex()


def commit_oid(tree: str, parent: str) -> str:
    raw = f"tree {tree}\nparent {parent}\nauthor Task 13 Fixture <fixture@example.invalid> 3 +0000\ncommitter Task 13 Fixture <fixture@example.invalid> 3 +0000\n\nTask 14 evidence E2\n"
    return oid("commit", raw.encode()).hex()


def binding(path: str, raw: bytes) -> dict[str, object]:
    return {
        "path": path,
        "mode": "100644",
        "blob_oid": oid("blob", raw).hex(),
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "byte_length": len(raw),
    }


class ReconciliationReceiptSchemaTests(unittest.TestCase):
    def test_v3_requires_the_exact_sorted_28_path_profile_and_predecessor(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["$id"], "gocode.project-owner.authority-receipt/3")
        self.assertFalse(_schema_errors(schema))
        self.assertFalse(_errors(schema, receipt()))
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.assertTrue(profile["fixture_only"])
        self.assertEqual(tuple(profile["required_paths"]), PATHS)
        subject_s2 = json.loads(SUBJECT_S2.read_text(encoding="utf-8"))
        evidence_e2 = json.loads(EVIDENCE_E2.read_text(encoding="utf-8"))
        self.assertNotEqual(evidence_e2["subject"], subject_s2)
        self.assertNotEqual(evidence_e2["subject"]["tree_oid"], subject_s2["tree_oid"])
        self.assertNotEqual(evidence_e2["subject"]["commit_oid"], subject_s2["commit_oid"])
        self.assertEqual(evidence_e2["predecessor_receipt_sha256"], profile["predecessor_receipt_sha256"])

    def test_s2_e2_fixture_graph_is_deterministic_non_self_referential_and_non_authoritative(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        initial, receipt_s2 = INITIAL.read_bytes(), RECEIPT_S2.read_bytes()
        signed = json.loads(receipt_s2)
        evidence = json.loads(EVIDENCE_E2.read_text(encoding="utf-8"))
        self.assertTrue(evidence["fixture_only"])
        self.assertEqual(initial, TASK13_INITIAL.read_bytes())
        self.assertEqual(evidence["initial_receipt_sha256"], hashlib.sha256(initial).hexdigest())
        self.assertEqual(evidence["receipt_s2_sha256"], hashlib.sha256(receipt_s2).hexdigest())
        self.assertEqual(signed["predecessor_receipt_sha256"], evidence["initial_receipt_sha256"])
        self.assertEqual(signed["subject"], json.loads(SUBJECT_S2.read_text(encoding="utf-8")))
        self.assertEqual(signed["subject"]["commit_oid"], commit_oid(signed["subject"]["tree_oid"], json.loads(initial)["subject"]["commit_oid"]))
        files = {path: (DOCUMENTS / path).read_bytes() for path in PATHS}
        files.update({
            "docs/evidence/V1_PLATFORM_SCOPE_AUTHORIZATION_RECEIPT.json": initial,
            "docs/evidence/POST_RC0_DOCUMENT_RECONCILIATION_RECEIPT.json": receipt_s2,
        })
        self.assertEqual(evidence["subject"]["tree_oid"], tree_oid(files))
        self.assertEqual(evidence["subject"]["commit_oid"], commit_oid(evidence["subject"]["tree_oid"], signed["subject"]["commit_oid"]))
        self.assertEqual(set(files) - {"docs/evidence/V1_PLATFORM_SCOPE_AUTHORIZATION_RECEIPT.json", "docs/evidence/POST_RC0_DOCUMENT_RECONCILIATION_RECEIPT.json"}, set(PATHS))
        self.assertNotIn("docs/evidence/POST_RC0_DOCUMENT_RECONCILIATION_E2.json", (item["path"] for item in signed["documents"]))
        for mutate in (lambda value: value.pop("predecessor_receipt_sha256"), lambda value: value["documents"].reverse(), lambda value: value["documents"].pop(), lambda value: value.update(predecessor_receipt_sha256="x" * 64)):
            changed = deepcopy(receipt()); mutate(changed); self.assertTrue(_errors(schema, changed))

    def test_s2_uses_exact_raw_document_bindings_and_git_subject(self) -> None:
        """Catches placeholder document hashes or a subject not derived from the raw fixture."""
        signed = json.loads(RECEIPT_S2.read_text(encoding="utf-8"))
        expected = []
        files: dict[str, bytes] = {}
        for path in PATHS:
            raw = (DOCUMENTS / path).read_bytes()
            files[path] = raw
            item = binding(path, raw)
            if path == PATHS[16]:
                item["schema_id"] = "gocode.v1-platform-scope-claim-migration/1"
            if path == PATHS[17]:
                item["schema_id"] = "gocode.rc0.post-rc0-platform-composed-universe/1"
            expected.append(item)
        self.assertEqual(signed["documents"], expected)
        subject = json.loads(SUBJECT_S2.read_text(encoding="utf-8"))
        self.assertEqual(subject["tree_oid"], tree_oid(files))
        self.assertEqual(
            subject["commit_oid"],
            commit_oid(subject["tree_oid"], json.loads(INITIAL.read_text(encoding="utf-8"))["subject"]["commit_oid"]),
        )

    def test_v3_schema_rejects_schema_ids_on_regular_paths_and_oid_width_mismatch(self) -> None:
        """Catches widening the closed profile or decoupling object format from its OIDs."""
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        for index in range(28):
            changed = receipt()
            if index not in (16, 17):
                changed["documents"][index]["schema_id"] = "gocode.unexpected/1"
            else:
                changed["documents"][index]["schema_id"] = "gocode.unexpected/1"
            self.assertTrue(_errors(schema, changed), index)
        changed = receipt()
        changed["subject"]["object_format"] = "sha256"
        changed["subject"]["commit_oid"] = "3" * 64
        changed["subject"]["tree_oid"] = "4" * 64
        changed["documents"][0]["blob_oid"] = "5" * 40
        self.assertTrue(_errors(schema, changed))

    def test_v3_schema_and_semantics_reject_u64_overflow_and_impossible_utc(self) -> None:
        """Catches Python/schema drift from the Rust u64 and UTC-calendar contract."""
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        too_large = receipt()
        too_large["key_epoch"] = 2**64
        too_large["documents"][0]["byte_length"] = 2**64
        self.assertTrue(_errors(schema, too_large))
        for issued_at in ("2026-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-01-01T24:00:00Z"):
            changed = receipt()
            changed["issued_at"] = issued_at
            self.assertTrue(reconciliation_receipt_errors(changed), issued_at)
        valid = receipt()
        valid["issued_at"] = "2024-02-29T23:59:59Z"
        self.assertFalse(reconciliation_receipt_errors(valid))


if __name__ == "__main__":
    unittest.main()
