import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.release_v2.dependencies import inventory_dependencies
from scripts.release_v2.dependencies_common import public_locator
from scripts.release_v2.dependency_specs import _cargo_version_matches
from scripts.release_v2.model import BuildInputIdentityV2, FailureCodeV1, ReleaseFailure


class DependencyBindingTests(unittest.TestCase):
    def test_cargo_caret_and_exact_specs_bind_one_direct_edge(self) -> None:
        with _fixture('foo = "1.2"', "foo 1.3.0 (registry+https://github.com/rust-lang/crates.io-index)", "1.3.0") as root:
            self.assertTrue(_inventory(root).packages[1].direct)
        with _fixture('foo = "=1.2.0"', "foo 1.3.0 (registry+https://github.com/rust-lang/crates.io-index)", "1.3.0") as root:
            _blocks(self, root)

    def test_cargo_zero_major_caret_and_missing_extra_edges_block(self) -> None:
        with _fixture('foo = "0.2"', "foo 0.3.0 (registry+https://github.com/rust-lang/crates.io-index)", "0.3.0") as root:
            _blocks(self, root)
        with _fixture('foo = "1.2"', "", "") as root:
            _blocks(self, root)
        with _fixture('foo = "1.2"', "foo 1.3.0 (registry+https://github.com/rust-lang/crates.io-index)\nbar 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)", "1.3.0", extra=True) as root:
            _blocks(self, root)

    def test_cargo_git_source_must_match_exact_manifest_revision(self) -> None:
        revision = "a" * 40
        declaration = f'foo = {{ git = "https://example.invalid/foo", rev = "{revision}" }}'
        with _fixture(declaration, "foo 1.2.0 (registry+https://github.com/rust-lang/crates.io-index)", "1.2.0") as root:
            _blocks(self, root)

    def test_cargo_rejects_ranges_and_custom_registry(self) -> None:
        with _fixture('foo = ">=1.2"', "foo 1.2.0 (registry+https://github.com/rust-lang/crates.io-index)", "1.2.0") as root:
            _blocks(self, root)
        with _fixture('foo = { version = "1.2.0", registry = "private" }', "foo 1.2.0 (registry+https://github.com/rust-lang/crates.io-index)", "1.2.0") as root:
            _blocks(self, root)

    def test_pnpm_accepts_only_exact_supported_specifiers(self) -> None:
        edge = "foo 1.2.3 (registry+https://github.com/rust-lang/crates.io-index)"
        with _fixture('foo = "1.2"', edge, "1.2.3", pnpm="1.2") as root:
            _blocks(self, root)
        with _fixture('foo = "1.2"', edge, "1.2.3", pnpm="^1.2.3") as root:
            _blocks(self, root)
        with _fixture('foo = "1.2"', edge, "1.2.3", pnpm="1.2.3") as root:
            package = next(item for item in _inventory(root).packages if item.ecosystem == "pnpm")
            self.assertTrue(package.direct)

    def test_parser_documents_and_rejects_nested_flow_collections(self) -> None:
        from scripts.release_v2.pnpm_lock_parser import parse_pnpm_lock

        self.assertIn("Grammar", parse_pnpm_lock.__doc__ or "")
        with self.assertRaises(ReleaseFailure):
            parse_pnpm_lock("lockfileVersion: '9.0'\nsettings: {nested: {value: true}}\n")

    def test_pnpm_peer_suffix_requires_exact_snapshot_for_direct_and_transitive_edges(self) -> None:
        with _fixture('foo = "1.2"', "foo 1.3.0 (registry+https://github.com/rust-lang/crates.io-index)", "1.3.0") as root:
            (root / "pnpm-lock.yaml").write_text(_pnpm_peer_lock("foo@1.2.3"))
            _blocks(self, root)
        with _fixture('foo = "1.2"', "foo 1.3.0 (registry+https://github.com/rust-lang/crates.io-index)", "1.3.0") as root:
            (root / "pnpm-lock.yaml").write_text(_pnpm_peer_lock("foo@1.2.3(peer@2.0.0)"))
            _blocks(self, root)

    def test_cargo_caret_bounds_follow_major_zero_rules(self) -> None:
        cases = (
            ("0.0.3", "0.0.3", True), ("0.0.3", "0.0.4", False), ("0.0.3", "0.0.2", False),
            ("0.2.3", "0.2.3", True), ("0.2.3", "0.2.99", True), ("0.2.3", "0.3.0", False), ("0.2.3", "0.2.2", False),
            ("1.2.3", "1.2.3", True), ("1.2.3", "1.99.99", True), ("1.2.3", "2.0.0", False), ("1.2.3", "1.2.2", False),
        )
        for spec, actual, expected in cases:
            with self.subTest(spec=spec, actual=actual):
                self.assertIs(_cargo_version_matches(spec, actual), expected)

    def test_url_authority_userinfo_delimiter_is_rejected_without_echoing_input(self) -> None:
        for value in ("https://@example.invalid/a", "https://:@example.invalid/a", "https://user@example.invalid/a", "https://user:secret@example.invalid/a"):
            with self.subTest(value=value):
                with self.assertRaises(ReleaseFailure) as raised:
                    public_locator(value)
                self.assertEqual(raised.exception.detail, "dependency_locator_invalid")
                self.assertNotIn(value, str(raised.exception))


def _blocks(case: unittest.TestCase, root: Path) -> None:
    with case.assertRaises(ReleaseFailure) as raised:
        _inventory(root)
    case.assertIs(raised.exception.code, FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE)


def _inventory(root: Path):
    return inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", (root / "Cargo.toml", root / "package.json"), _identity(root))


def _identity(root: Path) -> BuildInputIdentityV2:
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    return BuildInputIdentityV2("build-input-v2", "a" * 40, "b" * 64, "1.0.0", "x86_64-unknown-linux-gnu", "linux", ("c" * 64,), "rust-1.97.1", digest(root / "Cargo.lock"), digest(root / "pnpm-lock.yaml"), "release", 0)


class _fixture:
    def __init__(self, declaration: str, edge: str, version: str, *, extra: bool = False, pnpm: str | None = None) -> None:
        self.declaration, self.edge, self.version, self.extra, self.pnpm = declaration, edge, version, extra, pnpm

    def __enter__(self) -> Path:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        cargo_dependencies = self.edge or ""
        records = "" if not self.edge else _cargo_records(self.version, self.extra)
        (root / "Cargo.toml").write_text(f'[package]\nname = "app"\nversion = "1.0.0"\n[dependencies]\n{self.declaration}\n')
        (root / "Cargo.lock").write_text(f'version = 4\n[[package]]\nname = "app"\nversion = "1.0.0"\ndependencies = [{json.dumps(cargo_dependencies)}]\n{records}')
        specifier = self.pnpm or "1.2.3"
        (root / "package.json").write_text(json.dumps({"dependencies": {"foo": specifier}}))
        (root / "pnpm-lock.yaml").write_text(_pnpm_lock(specifier))
        return root

    def __exit__(self, *unused: object) -> None:
        self.temporary.cleanup()


def _cargo_records(version: str, extra: bool) -> str:
    suffix = "" if not extra else '\n[[package]]\nname = "bar"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + "b" * 64 + '"\n'
    return f'\n[[package]]\nname = "foo"\nversion = "{version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "{"a" * 64}"\n{suffix}'


def _pnpm_lock(specifier: str) -> str:
    return f"""lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      foo:
        specifier: {specifier}
        version: 1.2.3
packages:
  foo@1.2.3:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
snapshots:
  foo@1.2.3: {{}}
"""


def _pnpm_peer_lock(snapshot: str) -> str:
    return """lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      foo:
        specifier: 1.2.3
        version: 1.2.3(peer@2.0.0)
packages:
  foo@1.2.3:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
  peer@2.0.0:
    resolution:
      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
snapshots:
  """ + snapshot + """:
    dependencies:
      peer: 2.0.0(foo@1.2.3)
  peer@2.0.0: {}
"""
