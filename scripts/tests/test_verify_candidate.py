"""Verifier tests for the assembled Local Engine candidate (Plan Task
16 / release_verify): a well-formed candidate passes; a tampered
binary, a missing manifest artifact and a broken MANIFEST all reject.

Uses verify-candidate.py's verify() directly (no subprocess), mirroring
test_verify_qualification_matrix.py."""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "scripts/local-engine/verify-candidate.py"

_SPEC = importlib.util.spec_from_file_location("verify_candidate", VERIFIER)
vc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(vc)

TARGET = "aarch64-apple-darwin"


def make_candidate(root: Path) -> Path:
    binaries = root / "binaries"
    binaries.mkdir(parents=True, exist_ok=True)
    manifest = root / "MANIFEST.txt"
    lines = ["# local-engine Phase 1 candidate"]
    names = (
        "runned-" + TARGET,
        "runne-" + TARGET,
        "runne-llama-worker-" + TARGET,
    )
    import hashlib

    for name in names:
        blob = binaries / name
        blob.write_bytes(f"elf:{name}".encode())
        digest = hashlib.sha256(blob.read_bytes()).hexdigest()
        lines.append(f"sha256:{digest}  {name}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return root


class VerifyCandidate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        make_candidate(self.root)

    def test_well_formed_candidate_passes(self) -> None:
        self.assertEqual(vc.verify(self.root, TARGET), 3)

    def test_tampered_binary_rejects(self) -> None:
        (self.root / "binaries" / "runned").write_bytes(b"tampered")
        with self.assertRaises(vc.Rejection):
            vc.verify(self.root, TARGET)

    def test_missing_manifest_artifact_rejects(self) -> None:
        (self.root / "binaries" / "runne-llama-worker-aarch64-apple-darwin").unlink()
        with self.assertRaises(vc.Rejection):
            vc.verify(self.root, TARGET)

    def test_missing_required_sidecar_rejects(self) -> None:
        manifest = self.root / "MANIFEST.txt"
        lines = [
            line
            for line in manifest.read_text(encoding="utf-8").splitlines()
            if "runne-llama-worker" not in line
        ]
        manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(vc.Rejection):
            vc.verify(self.root, TARGET)

    def test_manifest_listed_extra_artifact_rejects(self) -> None:
        extra = self.root / "binaries" / f"stale-helper-{TARGET}"
        extra.write_bytes(b"stale")
        import hashlib

        digest = hashlib.sha256(extra.read_bytes()).hexdigest()
        manifest = self.root / "MANIFEST.txt"
        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            + f"sha256:{digest}  {extra.name}\n",
            encoding="utf-8",
        )
        with self.assertRaises(vc.Rejection):
            vc.verify(self.root, TARGET)

    def test_unlisted_directory_in_binaries_rejects(self) -> None:
        (self.root / "binaries" / "stale-helper").mkdir()
        with self.assertRaises(vc.Rejection):
            vc.verify(self.root, TARGET)

    def test_required_binary_symlink_to_outside_rejects(self) -> None:
        binary = self.root / "binaries" / f"runned-{TARGET}"
        outside = self.root / "outside-binary"
        shutil.copy2(binary, outside)
        binary.unlink()
        binary.symlink_to(outside)
        with self.assertRaises(vc.Rejection):
            vc.verify(self.root, TARGET)

    def test_duplicate_entry_rejects(self) -> None:
        manifest = self.root / "MANIFEST.txt"
        hash_line = [
            line
            for line in manifest.read_text(encoding="utf-8").splitlines()
            if line.startswith("sha256:")
        ][0]
        manifest.write_text(hash_line + "\n" + hash_line + "\n", encoding="utf-8")
        with self.assertRaises(vc.Rejection):
            vc.verify(self.root, TARGET)


if __name__ == "__main__":
    unittest.main()
