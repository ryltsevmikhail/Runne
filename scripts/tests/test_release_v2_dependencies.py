import hashlib
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.dependencies import inventory_dependencies
from scripts.release_v2.inventory import build_inventory
from scripts.release_v2.model import ArtifactEntry, BuildInputIdentityV2, FailureCodeV1, ProductTupleIdentityV1, ReleaseFailure
from scripts.release_v2.sbom import bind_sbom, build_sbom, validate_sbom
class DependencyTests(unittest.TestCase):
    def test_at_18_complete_cargo_pnpm_inventory(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        self.assertEqual(
            [(item.ecosystem, item.name, item.version, item.direct) for item in inventory.packages],
            [
                ("cargo", "app", "1.0.0", False),
                ("cargo", "serde", "1.0.0", True),
                ("pnpm", "left-pad", "1.3.0", True),
                ("pnpm", "transitive", "2.0.0", False),
            ],
        )
        serde = next(item for item in inventory.packages if item.name == "serde")
        self.assertEqual(serde.lock_locator, "https://github.com/rust-lang/crates.io-index")
        self.assertEqual(serde.source_digest, "a" * 64)
        self.assertIsNone(serde.declared_license)
        self.assertEqual(inventory.packages[0].declared_license, "Apache-2.0")
        self.assertEqual(inventory.packages[-1].dependencies, ())
    def test_at_18_missing_direct_or_transitive_dependency_blocks(self) -> None:
        with _fixture() as root:
            (root / "Cargo.lock").write_text(_CARGO_LOCK.replace('"serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"', '"missing 1.0.0"'))
            with self.assertRaises(ReleaseFailure) as raised:
                _inventory(root)
        self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)
    def test_missing_manifest_direct_dependency_blocks(self) -> None:
        with _fixture() as root:
            (root / "package.json").write_text(json.dumps({"dependencies": {"not-in-lock": "1.0.0"}}))
            with self.assertRaises(ReleaseFailure) as raised:
                _inventory(root)
        self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)
    def test_at_19_complete_transitive_closure_is_accepted(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        left_pad = next(item for item in inventory.packages if item.name == "left-pad")
        self.assertEqual(left_pad.dependencies, ("pnpm:transitive@2.0.0",))
    def test_at_19_missing_closure_member_blocks(self) -> None:
        with _fixture() as root:
            (root / "pnpm-lock.yaml").write_text(_PNPM_LOCK.replace("  transitive@2.0.0:\n", ""))
            with self.assertRaises(ReleaseFailure) as raised:
                _inventory(root)
        self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)
    def test_at_21_pinned_git_dependency_is_accepted(self) -> None:
        with _fixture() as root:
            pinned = "b" * 40
            (root / "Cargo.lock").write_text(_CARGO_LOCK.replace(
                _CARGO_SOURCE, f'source = "git+https://github.com/example/serde#{pinned}"'
            ).replace("registry+https://github.com/rust-lang/crates.io-index", f"git+https://github.com/example/serde#{pinned}")); (root / "Cargo.toml").write_text(_CARGO_MANIFEST.replace('serde = "1.0.0"', f'serde = {{ git = "https://github.com/example/serde", rev = "{pinned}" }}'))
            inventory = _inventory(root)
        serde = next(item for item in inventory.packages if item.name == "serde")
        self.assertEqual(serde.lock_locator, "https://github.com/example/serde")
        self.assertEqual(serde.source_digest, pinned)
    def test_at_21_unpinned_git_dependency_blocks(self) -> None:
        with _fixture() as root:
            (root / "Cargo.lock").write_text(_CARGO_LOCK.replace(
                _CARGO_SOURCE, 'source = "git+https://github.com/example/serde#main"'
            ).replace("registry+https://github.com/rust-lang/crates.io-index", "git+https://github.com/example/serde#main"))
            with self.assertRaises(ReleaseFailure) as raised:
                _inventory(root)
        self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)
    def test_at_22_credential_free_registry_locator_is_accepted(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        self.assertTrue(inventory.inventory_sha256)
    def test_at_22_registry_credential_url_is_redacted_and_blocks(self) -> None:
        with _fixture() as root:
            (root / "Cargo.lock").write_text(_CARGO_LOCK.replace(
                "https://github.com/rust-lang/crates.io-index", "https://user:top-secret@example.invalid/index"
            ))
            with self.assertRaises(ReleaseFailure) as raised:
                _inventory(root)
        self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)
        self.assertNotIn("top-secret", str(raised.exception))
    def test_workspace_cargo_and_pnpm_components_are_resolved_from_supplied_manifests(self) -> None:
        with _workspace_fixture() as root:
            inventory = inventory_dependencies(
                root / "Cargo.lock", root / "pnpm-lock.yaml", _workspace_manifests(root), _identity(root)
            )
        values = {(item.ecosystem, item.name): item for item in inventory.packages}
        self.assertEqual(values[("cargo", "local")].lock_locator, "workspace:local@1.0.0")
        self.assertTrue(values[("cargo", "local")].direct)
        self.assertEqual(values[("pnpm", "@example/local")].lock_locator, "workspace:@example/local@1.0.0")
        self.assertEqual(values[("pnpm", "@example/web")].dependencies, ("pnpm:@example/local@1.0.0", "pnpm:left-pad@1.3.0"))
        self.assertTrue(values[("pnpm", "left-pad")].direct)
    def test_workspace_missing_package_dependency_or_link_escape_blocks(self) -> None:
        with _workspace_fixture() as root:
            (root / "crates" / "app" / "Cargo.toml").write_text(_CARGO_WORKSPACE_APP.replace("local = { path = \"../local\" }", "missing = { path = \"../missing\" }"))
            with self.assertRaises(ReleaseFailure):
                inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", _workspace_manifests(root), _identity(root))
        with _workspace_fixture() as root:
            (root / "pnpm-lock.yaml").write_text(_PNPM_WORKSPACE_LOCK.replace("link:../local", "link:../../escape"))
            with self.assertRaises(ReleaseFailure):
                inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", _workspace_manifests(root), _identity(root))
    def test_bundled_inventory_requires_exact_declared_executable_components(self) -> None:
        with _fixture() as root:
            artifacts = root / "artifacts"
            artifacts.mkdir()
            executable = artifacts / "bin"
            executable.mkdir()
            executable.chmod(0o755)
            binary = executable / "runned"
            binary.write_bytes(b"daemon")
            binary.chmod(0o755)
            inventory = inventory_dependencies(
                root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"),
                _identity(root), _artifact_inventory(artifacts), ("bin/runned",),
            )
            bundled = next(item for item in inventory.packages if item.ecosystem == "bundled")
            self.assertEqual((bundled.name, bundled.source_digest), ("bin/runned", _sha256(b"daemon")))
            with self.assertRaises(ReleaseFailure):
                inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root), _artifact_inventory(artifacts), ())
            with self.assertRaises(ReleaseFailure):
                inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root), _artifact_inventory(artifacts), ("bin/runned", "bin/missing"))
    def test_inventory_is_deterministic_without_subprocess_or_socket_calls(self) -> None:
        with _fixture() as root, patch("subprocess.Popen", side_effect=AssertionError), patch("subprocess.run", side_effect=AssertionError), patch("socket.socket", side_effect=AssertionError), patch("socket.create_connection", side_effect=AssertionError):
            first = _inventory(root)
            second = _inventory(root)
        self.assertEqual(first.packages, second.packages)
        self.assertEqual(canonical_json(asdict(first)), canonical_json(asdict(second)))
        self.assertEqual(first.inventory_sha256, second.inventory_sha256)
    def test_at_20_unique_bom_refs_are_accepted(self) -> None:
        with _fixture() as root: inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        document = json.loads(raw)
        self.assertEqual(len({item["bom-ref"] for item in document["components"]}), len(document["components"]))
        self.assertEqual(len(document["components"]), len(inventory.packages) + 1)
        validate_sbom(raw, inventory, product, structural_fixture=True)
        document["components"][1]["bom-ref"] = document["components"][0]["bom-ref"]
        self._sbom_incomplete(lambda: validate_sbom(canonical_json(document), inventory, product, structural_fixture=True))
    def test_at_24_sbom_candidate_mismatch_blocks(self) -> None:
        with _fixture() as root: inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        document = json.loads(raw)
        document["metadata"]["properties"][0]["value"] = "0" * 64
        self._sbom_incomplete(lambda: validate_sbom(canonical_json(document), inventory, product, structural_fixture=True))
    def test_at_25_unsorted_sbom_blocks(self) -> None:
        with _fixture() as root: inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        document = json.loads(raw)
        document["components"] = list(reversed(document["components"]))
        self._sbom_incomplete(lambda: validate_sbom(canonical_json(document), inventory, product))
    def _sbom_incomplete(self, callback: object) -> None:
        with self.assertRaises(ReleaseFailure) as failure: callback()
        self.assertIs(failure.exception.code, FailureCodeV1.SBOM_INCOMPLETE)
def _inventory(root: Path):
    return inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root))
def _bound_sbom(inventory: object) -> tuple[bytes, ProductTupleIdentityV1]:
    product = ProductTupleIdentityV1("a" * 64, "b" * 64, "0" * 64, "c" * 64, "d" * 64, ("Desktop",), "product-tuple-v1")
    raw = build_sbom(inventory, product, structural_fixture=True)
    return raw, bind_sbom(product, raw)
def _identity(root: Path) -> BuildInputIdentityV2:
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    return BuildInputIdentityV2("build-input-v2", "a" * 40, "b" * 64, "1.0.0", "x86_64-unknown-linux-gnu", "linux", ("c" * 64,), "rust-1.97.1", digest(root / "Cargo.lock"), digest(root / "pnpm-lock.yaml"), "release", 0)
def _workspace_manifests(root: Path) -> tuple[Path, ...]:
    return tuple(root / path for path in ("Cargo.toml", "crates/app/Cargo.toml", "crates/local/Cargo.toml", "package.json", "apps/web/package.json", "apps/local/package.json"))
def _artifact_inventory(root: Path):
    return build_inventory(root, (ArtifactEntry("bin", "directory", "0755", 0, _sha256(b"")), ArtifactEntry("bin/runned", "file", "0755", 6, _sha256(b"daemon"))))
def _sha256(value: bytes) -> str:
    import hashlib
    return hashlib.sha256(value).hexdigest()
class _fixture:
    def __enter__(self) -> Path:
        self._temporary = tempfile.TemporaryDirectory()
        root = Path(self._temporary.name)
        (root / "Cargo.lock").write_text(_CARGO_LOCK)
        (root / "pnpm-lock.yaml").write_text(_PNPM_LOCK)
        (root / "Cargo.toml").write_text(_CARGO_MANIFEST)
        (root / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
        return root

    def __exit__(self, *unused: object) -> None:
        self._temporary.cleanup()
class _workspace_fixture:
    def __enter__(self) -> Path:
        self._temporary = tempfile.TemporaryDirectory()
        root = Path(self._temporary.name)
        for path, value in _WORKSPACE_FILES.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value)
        return root

    def __exit__(self, *unused: object) -> None:
        self._temporary.cleanup()
_CARGO_MANIFEST = "[package]\nname = \"app\"\nversion = \"1.0.0\"\nlicense = \"Apache-2.0\"\n[dependencies]\nserde = \"1.0.0\"\n"
_CARGO_SOURCE = 'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + "a" * 64 + '"'
_CARGO_LOCK = """version = 3

[[package]]
name = "app"
version = "1.0.0"
dependencies = ["serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "serde"
version = "1.0.0"
""" + _CARGO_SOURCE + """
"""
_PNPM_LOCK = """lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0
packages:
  left-pad@1.3.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
  transitive@2.0.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
snapshots:
  left-pad@1.3.0:
    dependencies:
      transitive: 2.0.0
  transitive@2.0.0: {}
"""
_CARGO_WORKSPACE_APP = """[package]
name = "app"
version = "1.0.0"
[dependencies]
serde = { workspace = true }
local = { path = "../local" }
"""
_CARGO_WORKSPACE_LOCK = """version = 3
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["local 1.0.0", "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]
[[package]]
name = "local"
version = "1.0.0"
[[package]]
name = "serde"
version = "1.0.0"
""" + _CARGO_SOURCE + "\n"
_PNPM_WORKSPACE_LOCK = """lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  apps/web:
    dependencies:
      @example/local:
        specifier: workspace:*
        version: link:../local
      left-pad:
        specifier: 1.3.0
        version: 1.3.0
packages:
  left-pad@1.3.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
  transitive@2.0.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
snapshots:
  left-pad@1.3.0:
    dependencies:
      transitive: 2.0.0
"""
_WORKSPACE_FILES = {
    "Cargo.toml": "[workspace]\nmembers = [\"crates/app\", \"crates/local\"]\n[workspace.dependencies]\nserde = \"1.0.0\"\n",
    "Cargo.lock": _CARGO_WORKSPACE_LOCK,
    "crates/app/Cargo.toml": _CARGO_WORKSPACE_APP,
    "crates/local/Cargo.toml": "[package]\nname = \"local\"\nversion = \"1.0.0\"\n",
    "package.json": json.dumps({"workspaces": ["apps/web", "apps/local"]}),
    "apps/web/package.json": json.dumps({"name": "@example/web", "version": "1.0.0", "dependencies": {"@example/local": "workspace:*", "left-pad": "1.3.0"}}),
    "apps/local/package.json": json.dumps({"name": "@example/local", "version": "1.0.0"}),
    "pnpm-lock.yaml": _PNPM_WORKSPACE_LOCK,
}
