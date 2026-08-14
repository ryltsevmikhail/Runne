"""Deterministic, non-authoritative initial two-commit ceremony vector."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts/project_owner_authority/fixtures/v2/initial-ceremony"
RECEIPT_PATH = "docs/evidence/V1_PLATFORM_SCOPE_AUTHORIZATION_RECEIPT.json"
PATHS = (
    "docs/adr/ADR-0027-v1-platform-scope.md",
    "docs/decisions/v1-platform-scope-v1.json",
    "docs/desktop/adr/ADR-0015-v1-platform-scope.md",
    "docs/schemas/v1-platform-scope-decision-v1.schema.json",
)
BLOBS = dict(zip(PATHS, ("runtime-adr.md", "decision.json", "desktop-adr.md", "decision-schema.json"), strict=True))


def load(name: str) -> dict:
    """Read one checked-in non-secret fixture descriptor."""
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def object_oid(kind: str, raw: bytes) -> bytes:
    """Return a Git SHA-1 object id without invoking Git or its object database."""
    return hashlib.sha1(f"{kind} {len(raw)}\0".encode() + raw).digest()


def tree_oid(paths: dict[str, bytes]) -> str:
    """Build recursive canonical Git tree bytes and return only their SHA-1 object id."""
    nested: dict[str, object] = {}
    for path, raw in paths.items():
        node = nested
        *parents, name = path.split("/")
        for parent in parents:
            node = node.setdefault(parent, {})  # type: ignore[assignment]
        node[name] = raw

    def encode(node: dict[str, object]) -> bytes:
        entries: list[tuple[str, str, bytes]] = []
        for name, value in node.items():
            if isinstance(value, dict):
                oid, mode = object_oid("tree", encode(value)), "40000"
            else:
                oid, mode = object_oid("blob", value), "100644"
            entries.append((name, mode, oid))
        entries.sort(key=lambda item: item[0] + ("/" if item[1] == "40000" else ""))
        return b"".join(f"{mode} ".encode() + name.encode() + b"\0" + oid for name, mode, oid in entries)

    return object_oid("tree", encode(nested)).hex()


def commit_oid(tree: str, timestamp: int, message: str, parent: str | None = None) -> str:
    """Build fixed raw commit bytes for the synthetic graph without a Git command."""
    raw = f"tree {tree}\n"
    if parent:
        raw += f"parent {parent}\n"
    raw += "author Task 13 Fixture <fixture@example.invalid> "
    raw += f"{timestamp} +0000\ncommitter Task 13 Fixture <fixture@example.invalid> {timestamp} +0000\n\n{message}\n"
    return object_oid("commit", raw.encode()).hex()


class InitialCeremonyTests(unittest.TestCase):
    def test_s_and_e_are_a_complete_non_self_referential_synthetic_graph(self) -> None:
        profile, subject_s, evidence_e = (load(name) for name in ("profile", "subject-s", "evidence-e"))
        receipt_raw = (FIXTURES / "receipt-s.json").read_bytes()
        receipt = json.loads(receipt_raw)
        source = {path: (FIXTURES / "blobs" / filename).read_bytes() for path, filename in BLOBS.items()}

        self.assertEqual(tuple(profile["required_paths"]), PATHS)
        self.assertEqual(tuple(item["path"] for item in receipt["documents"]), PATHS)
        self.assertNotIn(RECEIPT_PATH, profile["required_paths"])
        self.assertNotIn(RECEIPT_PATH, (item["path"] for item in receipt["documents"]))
        self.assertEqual(subject_s["tree_oid"], tree_oid(source))
        self.assertEqual(subject_s["commit_oid"], commit_oid(subject_s["tree_oid"], 0, "Task 13 subject S"))

        for binding in receipt["documents"]:
            raw = source[binding["path"]]
            self.assertEqual(binding["mode"], "100644")
            self.assertEqual(binding["blob_oid"], object_oid("blob", raw).hex())
            self.assertEqual(binding["content_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(binding["byte_length"], len(raw))

        evidence_files = source | {RECEIPT_PATH: receipt_raw}
        self.assertEqual(evidence_e["initial_receipt_sha256"], hashlib.sha256(receipt_raw).hexdigest())
        self.assertEqual(evidence_e["subject"]["tree_oid"], tree_oid(evidence_files))
        self.assertEqual(evidence_e["subject"]["commit_oid"], commit_oid(evidence_e["subject"]["tree_oid"], 1, "Task 13 evidence E", subject_s["commit_oid"]))
        self.assertNotEqual(evidence_e["subject"], subject_s)
        self.assertNotEqual(evidence_e["subject"]["tree_oid"], subject_s["tree_oid"])


if __name__ == "__main__":
    unittest.main()
