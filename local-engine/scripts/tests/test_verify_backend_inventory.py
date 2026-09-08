"""Tests for scripts/local-engine/verify_backend_inventory.py (Plan Task 1)."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERIFIER = REPO / "scripts" / "local-engine" / "verify_backend_inventory.py"
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
        "crates": [
            {"name": "hmac", "version": "0.12.1", "checksum": "a" * 64, "license": "MIT"},
            {"name": "llama-cpp-sys-2", "version": "0.1.152", "checksum": "b" * 64, "license": "MIT"},
        ],
        "features": {
            "llama-cpp-sys-2": {"allowed": ["metal", "default"], "recorded": ["metal"]}
        },
        "native": {
            "vendored_dir": "llama.cpp",
            "inside_crate": "llama-cpp-sys-2-0.1.152",
            "tree_digest": native_digest,
            "file_count": 2,
            "digest_method": "sha256-of-sorted-file-digests-v1",
        },
        "inventory": {"registry_crates": 2},
    }
    profile.update(overrides)
    path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return path

def write_lock(path: Path, checksum: str = "a" * 64, extra: str = "") -> Path:
    body = f'''version = 4

[[package]]
name = "hmac"
version = "0.12.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum}"
dependencies = []

[[package]]
name = "llama-cpp-sys-2"
version = "0.1.152"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{"b" * 64}"
dependencies = []
'''
    path.write_text(body + extra, encoding="utf-8")
    (path.parent / "Cargo.toml").write_text(
        '[workspace]\nresolver = "3"\n', encoding="utf-8"
    )
    return path

def write_native_tree(root: Path) -> Path:
    vendored = root / "llama-cpp-sys-2-0.1.152" / "llama.cpp"
    (vendored / "src").mkdir(parents=True)
    (vendored / "src" / "llama.cpp").write_bytes(b"model impl")
    (vendored / "include" / "llama.h").parent.mkdir(parents=True)
    (vendored / "include" / "llama.h").write_bytes(b"header")
    return vendored

class VerifierInventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="le-inventory-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    def write_cargo_metadata(self, native: Path, *, selected_features=None, declared_features=None,
                             package_name="llama-cpp-sys-2") -> Path:
        package_id = f"registry+https://example.invalid#{package_name}@0.1.152"
        hmac_id = "registry+https://example.invalid#hmac@0.12.1"
        metadata = {"packages": [{"id": hmac_id, "name": "hmac", "version": "0.12.1", "features": {}, "license": "MIT"}, {"id": package_id, "name": package_name,
                    "version": "0.1.152", "manifest_path": str(native.parent / "Cargo.toml"),
                    "features": declared_features if declared_features is not None else {"metal": [], "default": []}, "license": "MIT"}],
                    "resolve": {"nodes": [{"id": hmac_id, "features": []}, {"id": package_id, "features": selected_features if selected_features is not None else ["metal", "default"]}]}, "workspace_members": []}
        metadata_path = self.tmp / "cargo-metadata.json"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        cargo = self.tmp / "cargo"
        cargo.write_text(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" > \"${RUNNE_TEST_CARGO_LOG:?}\"\n"
            "cat \"${RUNNE_TEST_CARGO_METADATA:?}\"\n",
            encoding="utf-8",
        )
        cargo.chmod(0o755)
        return cargo
    def run_verifier(self, profile: Path, lock: Path, native: Path | None, *, metadata_native=None,
                     selected_features=None, declared_features=None, package_name="llama-cpp-sys-2"):
        metadata_native = metadata_native or native
        if metadata_native is None:
            metadata_native = write_native_tree(self.tmp / "unused-metadata")
        cargo = self.write_cargo_metadata(metadata_native, selected_features=selected_features,
                                          declared_features=declared_features, package_name=package_name)
        command = ["python3", str(VERIFIER), "--profile", str(profile), "--lock", str(lock)]
        if native is not None:
            command.extend(["--native-dir", str(native)])
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            env=os.environ
            | {
                "CARGO": str(cargo),
                "RUNNE_TEST_CARGO_LOG": str(self.tmp / "cargo-args.txt"),
                "RUNNE_TEST_CARGO_METADATA": str(self.tmp / "cargo-metadata.json"),
            },
        )
    def test_accepts_consistent_inventory(self):
        native = write_native_tree(self.tmp / "native")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        lock = write_lock(self.tmp / "Cargo.lock")
        result = self.run_verifier(profile, lock, native)
        self.assertEqual(result.returncode, 0, f"expected accept, got: {result.stderr}")
    def test_rejects_unpinned_crate_in_lock(self):
        native = write_native_tree(self.tmp / "n1")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        extra = (
            "\n[[package]]\n"
            'name = "undeclared-crate"\n'
            'version = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{"b" * 64}"\n'
        )
        lock = write_lock(self.tmp / "Cargo.lock", extra=extra)
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unpinned", (result.stderr + result.stdout).lower())
    def test_rejects_git_source_without_checksum(self):
        native = write_native_tree(self.tmp / "git-source")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        extra = ('\n[[package]]\nname = "git-crate"\nversion = "1.0.0"\n'
                 'source = "git+https://example.invalid/crate#deadbeef"\n')
        result = self.run_verifier(profile, write_lock(self.tmp / "Cargo.lock", extra=extra), native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-registry", (result.stderr + result.stdout).lower())
    def test_rejects_source_less_package_outside_workspace_metadata(self):
        native = write_native_tree(self.tmp / "outside-path")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        extra = '\n[[package]]\nname = "outside-path"\nversion = "1.0.0"\n'
        result = self.run_verifier(profile, write_lock(self.tmp / "Cargo.lock", extra=extra), native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("workspace", (result.stderr + result.stdout).lower())
    def test_rejects_stale_registry_crate_count(self):
        native = write_native_tree(self.tmp / "stale-count")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        data = json.loads(profile.read_text(encoding="utf-8"))
        data["inventory"]["registry_crates"] = 1
        profile.write_text(json.dumps(data), encoding="utf-8")
        result = self.run_verifier(profile, write_lock(self.tmp / "Cargo.lock"), native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("registry_crates", (result.stderr + result.stdout).lower())
    def test_rejects_changed_checksum(self):
        native = write_native_tree(self.tmp / "n2")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        lock = write_lock(self.tmp / "Cargo.lock", checksum="c" * 64)
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", (result.stderr + result.stdout).lower())
    def test_rejects_placeholder_or_mismatched_license(self):
        native = write_native_tree(self.tmp / "n3")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        for license_id in ("true", "Apache-2.0"):
            profile_data = json.loads(profile.read_text(encoding="utf-8"))
            profile_data["crates"][1]["license"] = license_id
            profile.write_text(json.dumps(profile_data), encoding="utf-8")
            result = self.run_verifier(profile, write_lock(self.tmp / "Cargo.lock"), native)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("license", (result.stderr + result.stdout).lower())
    def test_rejects_phantom_profile_pin(self):
        native = write_native_tree(self.tmp / "phantom")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        profile_data = json.loads(profile.read_text(encoding="utf-8"))
        profile_data["crates"].append(
            {
                "name": "phantom",
                "version": "9.9.9",
                "checksum": "c" * 64,
                "license": "MIT",
            }
        )
        profile.write_text(json.dumps(profile_data), encoding="utf-8")
        result = self.run_verifier(profile, write_lock(self.tmp / "Cargo.lock"), native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("profile pin", (result.stderr + result.stdout).lower())
    def test_rejects_profile_when_no_registry_pin_matches_lock(self):
        native = write_native_tree(self.tmp / "zero-matches")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        lock = (self.tmp / "Cargo.lock")
        lock.write_text("version = 4\n", encoding="utf-8")
        (self.tmp / "Cargo.toml").write_text(
            '[workspace]\nresolver = "3"\n', encoding="utf-8"
        )
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("profile pin", (result.stderr + result.stdout).lower())
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
    def test_rejects_claimed_feature_missing_from_cargo_metadata(self):
        native = write_native_tree(self.tmp / "feature-metadata")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        result = self.run_verifier(
            profile,
            write_lock(self.tmp / "Cargo.lock"),
            native,
            selected_features=["default"],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("allow", (result.stderr + result.stdout).lower())
    def test_rejects_active_feature_outside_profile_allowlist(self):
        native = write_native_tree(self.tmp / "feature-drift")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        result = self.run_verifier(
            profile, write_lock(self.tmp / "Cargo.lock"), native,
            selected_features=["default", "metal", "cuda"],
            declared_features={"default": [], "metal": [], "cuda": []},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("allow", (result.stderr + result.stdout).lower())
    def test_rejects_allowed_feature_missing_from_cargo_metadata(self):
        native = write_native_tree(self.tmp / "feature-missing")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        profile_data = json.loads(profile.read_text(encoding="utf-8"))
        profile_data["features"]["llama-cpp-sys-2"]["allowed"].append("common")
        profile.write_text(json.dumps(profile_data), encoding="utf-8")
        result = self.run_verifier(profile, write_lock(self.tmp / "Cargo.lock"), native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("allow", (result.stderr + result.stdout).lower())
    def test_rejects_claimed_feature_absent_from_cargo_manifest(self):
        native = write_native_tree(self.tmp / "feature-manifest")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        result = self.run_verifier(
            profile,
            write_lock(self.tmp / "Cargo.lock"),
            native,
            declared_features={"default": []},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest", (result.stderr + result.stdout).lower())
    def test_rejects_unrecorded_embedded_source(self):
        native = write_native_tree(self.tmp / "n5")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        lock = write_lock(self.tmp / "Cargo.lock")
        (native / "src" / "extra-file.cpp").write_bytes(b"unrecorded bytes")
        result = self.run_verifier(profile, lock, native)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native tree", (result.stderr + result.stdout).lower())
    def test_derives_native_dir_from_resolved_cargo_package(self):
        native = write_native_tree(self.tmp / "missing-native")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        result = self.run_verifier(profile, write_lock(self.tmp / "Cargo.lock"), None)
        self.assertEqual(result.returncode, 0, result.stderr)
    def test_uses_exact_native_worker_feature_for_cargo_metadata(self):
        native = write_native_tree(self.tmp / "metadata-feature")
        profile = write_profile(self.tmp / "profile.json", tree_digest(native))
        result = self.run_verifier(profile, write_lock(self.tmp / "Cargo.lock"), native)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = (self.tmp / "cargo-args.txt").read_text(encoding="utf-8")
        self.assertIn("--features runne-llama-worker/backend-llama-cpp", arguments)
        self.assertNotIn("--all-features", arguments)
    def test_rejects_native_dir_not_owned_by_resolved_cargo_package(self):
        expected = write_native_tree(self.tmp / "resolved-package")
        alternate = write_native_tree(self.tmp / "alternate")
        profile = write_profile(self.tmp / "profile.json", tree_digest(expected))
        lock = write_lock(self.tmp / "Cargo.lock")
        result = self.run_verifier(
            profile,
            lock,
            alternate,
            metadata_native=expected,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resolved cargo package", (result.stderr + result.stdout).lower())
if __name__ == "__main__":
    unittest.main()
