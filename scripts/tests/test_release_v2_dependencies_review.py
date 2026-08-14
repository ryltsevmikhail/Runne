import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release_v2.dependencies import inventory_dependencies
from scripts.release_v2.model import BuildInputIdentityV2, FailureCodeV1, ReleaseFailure
from scripts.release_v2.pnpm_lock_parser import parse_pnpm_lock


class DependencyReviewTests(unittest.TestCase):
    def test_real_root_inputs_are_complete_deterministic_and_offline(self) -> None:
        root = Path(__file__).parents[2]
        manifests = _root_manifests(root)
        parsed = parse_pnpm_lock((root / "pnpm-lock.yaml").read_text())
        self.assertEqual((len(parsed["packages"]), len(parsed["snapshots"])), (382, 382))
        with patch("subprocess.Popen", side_effect=AssertionError), patch("subprocess.run", side_effect=AssertionError), patch("socket.socket", side_effect=AssertionError), patch("socket.create_connection", side_effect=AssertionError):
            first = inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", manifests, _identity(root))
            second = inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", manifests, _identity(root))
        self.assertEqual(first.inventory_sha256, second.inventory_sha256)
        self.assertEqual(first.inventory_sha256, "34d372dd8be9e17af5d3bfb7210b6b4153e47b2abbb72c9acb094c44f21fcca7")
        self.assertEqual(sum(item.ecosystem == "cargo" for item in first.packages), 598)
        self.assertEqual(sum(item.ecosystem == "pnpm" for item in first.packages), 387)
        self.assertEqual(sum(len(item.dependencies) for item in first.packages if item.ecosystem == "pnpm"), 606)

    def test_lock_identity_mismatch_blocks_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.lock").write_text("not toml")
            (root / "pnpm-lock.yaml").write_text("not yaml")
            with self.assertRaises(ReleaseFailure) as raised:
                inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (), _mismatched_identity(root))
        self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)

    def test_cargo_direct_uses_exact_locked_version_and_source(self) -> None:
        with _cargo_versions() as root:
            inventory = inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", _cargo_manifests(root), _identity(root))
        versions = {item.version: item.direct for item in inventory.packages if item.ecosystem == "cargo" and item.name == "serde"}
        self.assertEqual(versions, {"1.0.0": True, "2.0.0": True, "3.0.0": False})

    def test_pnpm_mismatch_credentials_and_inline_comments_block(self) -> None:
        for replacement in ("version: 2.0.0", "integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA== # no", "tarball: https://user:secret@example.invalid/a"):
            with self.subTest(replacement=replacement), _pnpm_fixture() as root:
                lock = (root / "pnpm-lock.yaml")
                lock.write_text(lock.read_text().replace("version: 1.0.0", replacement, 1) if replacement.startswith("version") else lock.read_text().replace("integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", replacement, 1))
                with self.assertRaises(ReleaseFailure) as raised:
                    inventory_dependencies(root / "Cargo.lock", lock, (root / "Cargo.toml", root / "package.json"), _identity(root))
                self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)
                self.assertNotIn("secret", str(raised.exception))

    def test_pnpm_alias_and_peer_suffix_resolve_to_locked_package(self) -> None:
        with _pnpm_fixture() as root:
            (root / "package.json").write_text('{"dependencies": {"alias": "npm:foo@1.0.0"}}')
            (root / "pnpm-lock.yaml").write_text(_PNPM_ALIAS_LOCK)
            inventory = inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root))
        package = next(item for item in inventory.packages if item.ecosystem == "pnpm" and item.name == "foo")
        self.assertTrue(package.direct)
        self.assertEqual(package.dependencies, ("pnpm:peer@2.0.0",))

    def test_pnpm_alias_version_without_prefix_resolves_the_exact_snapshot(self) -> None:
        with _pnpm_fixture() as root:
            (root / "package.json").write_text('{"dependencies": {"alias": "npm:foo@1.0.0"}}')
            (root / "pnpm-lock.yaml").write_text(_PNPM_ALIAS_LOCK.replace("version: npm:foo@1.0.0(peer@2.0.0)", "version: foo@1.0.0(peer@2.0.0)"))
            inventory = inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root))
        package = next(item for item in inventory.packages if item.ecosystem == "pnpm" and item.name == "foo")
        self.assertTrue(package.direct)

    def test_pnpm_manifest_specifier_must_bind_the_matching_importer_identity(self) -> None:
        with _pnpm_fixture() as root:
            (root / "pnpm-lock.yaml").write_text(_PNPM_TWO_VERSION_LOCK)
            with self.assertRaises(ReleaseFailure) as raised:
                inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root))
            (root / "pnpm-lock.yaml").write_text(_PNPM_TWO_VERSION_LOCK.replace("specifier: 2.0.0\n        version: 2.0.0", "specifier: 1.0.0\n        version: 1.0.0"))
            inventory = inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root))
        self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)
        direct = {item.version: item.direct for item in inventory.packages if item.ecosystem == "pnpm" and item.name == "foo"}
        self.assertEqual(direct, {"1.0.0": True, "2.0.0": False})

    def test_pnpm_manifest_dependency_requires_a_corresponding_importer(self) -> None:
        with _pnpm_fixture() as root:
            (root / "pnpm-lock.yaml").write_text(_PNPM_LOCK.replace("importers:\n  .:\n    dependencies:\n      foo:\n        specifier: 1.0.0\n        version: 1.0.0", "importers: {}"))
            with self.assertRaises(ReleaseFailure) as raised:
                inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root))
        self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)

    def test_pnpm_parser_accepts_double_quoted_scalars_and_simple_flow_mappings(self) -> None:
        parsed = parse_pnpm_lock('lockfileVersion: "9.0"\nsettings: {autoInstallPeers: true, excludeLinksFromLockfile: false}\nimporters: {}\npackages: {}\nsnapshots: {}\n')
        self.assertEqual(parsed["lockfileVersion"], "9.0")
        self.assertEqual(parsed["settings"], {"autoInstallPeers": "true", "excludeLinksFromLockfile": "false"})

    def test_pnpm_parser_rejects_unsupported_yaml_forms(self) -> None:
        for value in ("{outer: {inner: value}}", "[value, {nested: value}]", "[value, !tag]", "value &anchor", "!tag value", "|\n  continuation", "value # comment"):
            with self.subTest(value=value):
                with self.assertRaises(ReleaseFailure) as raised:
                    parse_pnpm_lock(f"value: {value}\n")
                self.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)


def _identity(root: Path) -> BuildInputIdentityV2:
    return BuildInputIdentityV2("build-input-v2", "a" * 40, "b" * 64, "1.0.0", "x86_64-unknown-linux-gnu", "linux", ("c" * 64,), "rust-1.97.1", _digest(root / "Cargo.lock"), _digest(root / "pnpm-lock.yaml"), "release", 0)


def _mismatched_identity(root: Path) -> BuildInputIdentityV2:
    identity = _identity(root)
    return BuildInputIdentityV2(identity.schema_version, identity.source_revision, identity.source_tree_sha256, identity.release_version, identity.target, identity.platform, identity.profile_digests, identity.toolchain, "0" * 64, identity.pnpm_lock_sha256, identity.release_profile, identity.source_date_epoch)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _root_manifests(root: Path) -> tuple[Path, ...]:
    cargo = (root / "Cargo.toml", *sorted((root / "crates").glob("*/Cargo.toml")), root / "apps/desktop/src-tauri/Cargo.toml")
    pnpm = (root / "package.json", root / "apps/desktop/package.json", root / "contracts/gocode-ui-client-2/package.json", root / "packages/platform-contract/package.json", root / "packages/product/package.json")
    return cargo + pnpm


def _cargo_manifests(root: Path) -> tuple[Path, ...]:
    return (root / "Cargo.toml", root / "a/Cargo.toml", root / "b/Cargo.toml", root / "package.json")


class _cargo_versions:
    def __enter__(self) -> Path:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "a").mkdir()
        (root / "b").mkdir()
        (root / "Cargo.toml").write_text("[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"3\"\n")
        (root / "a/Cargo.toml").write_text("[package]\nname = \"a\"\nversion = \"1.0.0\"\n[dependencies]\nserde = \"1\"\n")
        (root / "b/Cargo.toml").write_text("[package]\nname = \"b\"\nversion = \"1.0.0\"\n[dependencies]\nserde = \"2\"\n")
        (root / "package.json").write_text("{}")
        (root / "Cargo.lock").write_text(_CARGO_LOCK)
        (root / "pnpm-lock.yaml").write_text(_EMPTY_PNPM_LOCK)
        return root

    def __exit__(self, *unused: object) -> None:
        self.temporary.cleanup()


class _pnpm_fixture:
    def __enter__(self) -> Path:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "Cargo.toml").write_text("[package]\nname = \"app\"\nversion = \"1.0.0\"\n")
        (root / "Cargo.lock").write_text("version = 4\n[[package]]\nname = \"app\"\nversion = \"1.0.0\"\n")
        (root / "package.json").write_text("{\"dependencies\": {\"foo\": \"1.0.0\"}}")
        (root / "pnpm-lock.yaml").write_text(_PNPM_LOCK)
        return root

    def __exit__(self, *unused: object) -> None:
        self.temporary.cleanup()


_EMPTY_PNPM_LOCK = "lockfileVersion: '9.0'\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\nimporters:\n  .: {}\npackages: {}\nsnapshots: {}\n"
_CARGO_LOCK = """version = 4
[[package]]
name = "a"
version = "1.0.0"
dependencies = ["serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]
[[package]]
name = "b"
version = "1.0.0"
dependencies = ["serde 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[[package]]
name = "serde"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
[[package]]
name = "serde"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
"""
_PNPM_LOCK = """lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      foo:
        specifier: 1.0.0
        version: 1.0.0
packages:
  foo@1.0.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
snapshots:
  foo@1.0.0: {}
"""
_PNPM_ALIAS_LOCK = """lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      alias:
        specifier: npm:foo@1.0.0
        version: npm:foo@1.0.0(peer@2.0.0)
packages:
  foo@1.0.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
  peer@2.0.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
snapshots:
  foo@1.0.0(peer@2.0.0):
    dependencies:
      peer: 2.0.0
  peer@2.0.0: {}
"""
_PNPM_TWO_VERSION_LOCK = """lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      foo:
        specifier: 2.0.0
        version: 2.0.0
packages:
  foo@1.0.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
  foo@2.0.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
snapshots:
  foo@1.0.0: {}
  foo@2.0.0: {}
"""
