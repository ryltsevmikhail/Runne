"""Tests for scripts/local-engine/verify_backend_inventory.py (Plan Task 1, Step 1).

RED-first contract: every case below must FAIL (non-zero verifier exit or
missing module) until the backend inventory verifier and profile exist.
Run: python3 -m unittest scripts/tests/test_verify_backend_inventory.py
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERIFIER = REPO / "scripts" / "local-engine" / "verify_backend_inventory.py"


def sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def tree_digest(dirpath: Path) -> str:
    """Same algorithm as the verifier: sha256 of sorted 'filehash  relpath' lines."""
    import hashlib

    lines = []
    for d, dirnames, files in os.walk(dirpath):
        dirnames.sort()
        for fn in sorted(files):
            p = Path(d) / fn
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            lines.append(f"{h}  {p.relative_to(dirpath).as_posix()}")
    blob = "\n".join(sorted(lines)) + "\n"
    return hashlib.sha256(blob.encode()).hexdigest()


def write_profile(path: Path, native_digest: str, **overrides) -> Path:
    profile = {
        "schema_version": "Phase1BackendProfileV1",
        "profile_ids": [
            "llama-cpp-cpu-macos-arm64-v1",
            "llama-cpp-metal-macos-arm64-v1",
        ],
        "target_triple": "aarch64-apple-darwin",
        "crates": [
            {
                "name": "hmac",
                "version": "0.12.1",
                "checksum": "a" * 64,
                "license": "MIT",
            }
        ],
        "features": {
            "llama-cpp-sys-2": {"allowed": ["metal"], "recorded": ["metal"]}
        },
        "native": {
            "vendored_dir": "llama.cpp",
            "tree_digest": native_digest,
            "digest_method": "sha256-of-sorted-file-digests-v1",
        },
    }
    profile.update(overrides)
    path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return path


def write_lock(path: Path, checksum: str = "a" * 64, extra: str = "") -> Path:
    body = (
        "version = 4\n\n"
        "[[package]]\n"
        'name = "hmac"\n'
        'version = "0.12.1"\n'
        f'checksum = "{checksum}"\n'
        "dependencies = []\n"
    )
    path.write_text(body + extra, encoding="utf-8")
    return path


def write_native_tree(root: Path) -> Path:
    vendored = root / "llama.cpp"
    (vendored / "src").mkdir(parents=True)
    (vendored / "src" / "llama.cpp").write_bytes(b"model impl")
    (vendored / "include" / "llama.h").parent.mkdir(parents=True)
    (vendored / "include" / "llama.h").write_bytes(b"header")
    return vendored


class VerifierInventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="le-inventory-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_verifier(self, profile: Path, lock: Path, native: Path):
        return subprocess.run(
            [
                "python3",
                str(VERIFIER),
                "--profile",
                str(profile),
                "--lock",
                str(lock),
                "--native-dir",
                str(native),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_verifier_exists(self):
        self.assertTrue(
            VERIFIER.is_file(), f"missing verifier: {VERIFIER}"
        )

    def test_accepts_consistent_inventory(self):
        native = write_native_tree(self.tmp / "native")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        lock = write_lock(self.tmp / "Cargo.lock")
        result = self.run_verifier(profile, lock, native)
        self.assertEqual(
            result.returncode, 0, f"expected accept, got: {result.stderr}"
        )

    def test_rejects_unpinned_crate_in_lock(self):
        native = write_native_tree(self.tmp / "n1")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        extra = (
            "\n[[package]]\n"
            'name = "undeclared-crate"\n'
            'version = "1.0.0"\n'
            f'checksum = "{"b" * 64}"\n'
        )
        lock = write_lock(self.tmp / "Cargo.lock", extra=extra)
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unpinned", (result.stderr + result.stdout).lower())

    def test_rejects_changed_checksum(self):
        native = write_native_tree(self.tmp / "n2")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        lock = write_lock(self.tmp / "Cargo.lock", checksum="c" * 64)
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", (result.stderr + result.stdout).lower())

    def test_rejects_missing_license(self):
        native = write_native_tree(self.tmp / "n3")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        profile_data = json.loads(profile.read_text(encoding="utf-8"))
        del profile_data["crates"][0]["license"]
        profile.write_text(json.dumps(profile_data), encoding="utf-8")
        lock = write_lock(self.tmp / "Cargo.lock")
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("license", (result.stderr + result.stdout).lower())

    def test_rejects_unknown_build_feature(self):
        native = write_native_tree(self.tmp / "n4")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        profile_data = json.loads(profile.read_text(encoding="utf-8"))
        profile_data["features"]["llama-cpp-sys-2"]["recorded"].append("cuda")
        profile.write_text(json.dumps(profile_data), encoding="utf-8")
        lock = write_lock(self.tmp / "Cargo.lock")
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("feature", (result.stderr + result.stdout).lower())

    def test_rejects_unrecorded_embedded_source(self):
        native = write_native_tree(self.tmp / "n5")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        lock = write_lock(self.tmp / "Cargo.lock")
        (native / "src" / "extra-file.cpp").write_bytes(b"unrecorded bytes")
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest", (result.stderr + result.stdout).lower())


if __name__ == "__main__":
    unittest.main()
