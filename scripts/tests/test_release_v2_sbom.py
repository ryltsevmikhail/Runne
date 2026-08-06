import base64
import hashlib
import json
import unittest
from pathlib import Path

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.dependencies import inventory_dependencies
from scripts.release_v2.dependencies_types import DependencyPackageV1
from scripts.release_v2.model import BuildInputIdentityV2, FailureCodeV1, ProductTupleIdentityV1, ReleaseFailure
from scripts.release_v2.sbom import bind_sbom, build_sbom, validate_sbom
from scripts.tests.release_v2_support import dependency_inventory


class SbomTests(unittest.TestCase):
    def test_bundled_component_serializes_safe_path_purl_hash_and_properties(self) -> None:
        digest = hashlib.sha256(b"gocoded").hexdigest()
        inventory = _inventory(_package("bundled", "bin/gocoded", digest, "artifact:bin/gocoded", digest, None))
        document = json.loads(build_sbom(inventory, _product(), structural_fixture=True))
        component = next(item for item in document["components"] if item["name"] == "bin/gocoded")
        self.assertEqual(component["bom-ref"], f"pkg:generic/gocode-bundled/bin/gocoded@{digest}")
        self.assertEqual(component["purl"], component["bom-ref"])
        self.assertEqual(component["hashes"], [{"alg": "SHA-256", "content": digest}])
        self.assertEqual(_properties(component), {"gocode:bundled-path": "bin/gocoded", "gocode:direct-transitive": "DIRECT", "gocode:license-disposition": "UNKNOWN", "gocode:lock-locator": "artifact:bin/gocoded", "gocode:source-kind": "bundled"})
        for unsafe in ("../gocoded", "bin/../gocoded", "bin\\gocoded"):
            with self.subTest(unsafe=unsafe):
                bad = _inventory(_package("bundled", unsafe, digest, f"artifact:{unsafe}", digest, None))
                _blocks(self, lambda: build_sbom(bad, _product(), structural_fixture=True))

    def test_source_digests_are_exact_required_and_normalized(self) -> None:
        sri_bytes = bytes(range(64))
        sri = "sha512-" + base64.b64encode(sri_bytes).decode("ascii")
        inventory = _inventory(
            _package("cargo", "cargo-pkg", "1.0.0", "https://crates.io/index", "a" * 64, "MIT"),
            _package("pnpm", "npm-pkg", "1.0.0", "npm:npm-pkg@1.0.0", sri, "MIT"),
            _package("cargo", "local", "1.0.0", "workspace:local@1.0.0", "b" * 64, "MIT"),
        )
        document = json.loads(build_sbom(inventory, _product()))
        components = {item["name"]: item for item in document["components"]}
        self.assertEqual(components["cargo-pkg"]["hashes"], [{"alg": "SHA-256", "content": "a" * 64}])
        self.assertEqual(components["npm-pkg"]["hashes"], [{"alg": "SHA-512", "content": sri_bytes.hex()}])
        self.assertEqual(components["local"]["hashes"], [{"alg": "SHA-256", "content": "b" * 64}])
        self.assertEqual(_properties(components["npm-pkg"])["gocode:lock-locator"], "npm:npm-pkg@1.0.0")
        for ecosystem, digest in (("cargo", "not-a-digest"), ("pnpm", "sha512-not-base64"), ("pnpm", "sha256-" + "A" * 43 + "=")):
            with self.subTest(ecosystem=ecosystem, digest=digest):
                package = _package(ecosystem, "bad-pkg", "1.0.0", "npm:bad-pkg@1.0.0", digest, "MIT")
                _blocks(self, lambda: build_sbom(_inventory(package), _product()))

    def test_unknown_license_is_structural_only_and_known_license_is_production_valid(self) -> None:
        unknown = _inventory(_package("cargo", "unknown", "1.0.0", "https://crates.io/index", "a" * 64, None))
        _blocks(self, lambda: build_sbom(unknown, _product()))
        raw = build_sbom(unknown, _product(), structural_fixture=True)
        document = json.loads(raw)
        component = next(item for item in document["components"] if item["name"] == "unknown")
        self.assertEqual(component["licenses"], [{"license": {"name": "UNKNOWN"}}])
        self.assertEqual(_properties(component)["gocode:license-disposition"], "UNKNOWN")
        bound = bind_sbom(_product(), raw)
        validate_sbom(raw, unknown, bound, structural_fixture=True)
        _blocks(self, lambda: validate_sbom(raw, unknown, bound))
        known = _inventory(_package("cargo", "known", "1.0.0", "https://crates.io/index", "a" * 64, "MIT"))
        known_raw = build_sbom(known, _product())
        validate_sbom(known_raw, known, bind_sbom(_product(), known_raw))

    def test_rebound_adversarial_structural_mutations_are_rejected(self) -> None:
        inventory = _inventory(_package("cargo", "known", "1.0.0", "https://crates.io/index", "a" * 64, "MIT"))
        raw = build_sbom(inventory, _product())
        cases = {
            "duplicate-bom-ref": lambda document: document["components"].__setitem__(1, {**document["components"][1], "bom-ref": document["components"][0]["bom-ref"]}),
            "candidate-property": lambda document: _metadata_property(document, "gocode:candidate-sha256").update(value="0" * 64),
            "product-property": lambda document: _metadata_property(document, "gocode:product-components-sha256").update(value="0" * 64),
            "component-order": lambda document: document.update(components=list(reversed(document["components"]))),
            "unknown-component": lambda document: document["components"].append({**document["components"][1], "bom-ref": "pkg:cargo/extra@1.0.0", "name": "extra", "purl": "pkg:cargo/extra@1.0.0"}),
        }
        document = json.loads(raw)
        self.assertIn("gocode:candidate-sha256", _properties(document["metadata"]))
        for name, mutate in cases.items():
            with self.subTest(name=name):
                changed = json.loads(raw)
                mutate(changed)
                candidate = canonical_json(changed)
                _blocks(self, lambda: validate_sbom(candidate, inventory, bind_sbom(_product(), candidate)))

    def test_root_structural_sbom_is_deterministic_with_bundled_component_and_production_blocks_unknowns(self) -> None:
        root = Path(__file__).parents[2]
        manifests = (root / "Cargo.toml", *sorted((root / "crates").glob("*/Cargo.toml")), root / "apps/desktop/src-tauri/Cargo.toml", root / "package.json", root / "apps/desktop/package.json", root / "contracts/gocode-ui-client-1/package.json", root / "packages/platform-contract/package.json", root / "packages/product/package.json")
        identity = BuildInputIdentityV2("build-input-v2", "a" * 40, "b" * 64, "1.0.0", "x86_64-unknown-linux-gnu", "linux", ("c" * 64,), "rust-1.97.1", _sha256(root / "Cargo.lock"), _sha256(root / "pnpm-lock.yaml"), "release", 0)
        source = inventory_dependencies(root / "Cargo.lock", root / "pnpm-lock.yaml", manifests, identity)
        bundled_digest = hashlib.sha256(b"gocoded").hexdigest()
        inventory = _inventory(*source.packages, _package("bundled", "bin/gocoded", bundled_digest, "artifact:bin/gocoded", bundled_digest, None))
        first = build_sbom(inventory, _product(), structural_fixture=True)
        second = build_sbom(inventory, _product(), structural_fixture=True)
        self.assertEqual(first, second)
        self.assertEqual(len(json.loads(first)["components"]), 987)
        _blocks(self, lambda: build_sbom(inventory, _product()))


def _package(ecosystem: str, name: str, version: str, locator: str, digest: str, license_name: str | None) -> DependencyPackageV1:
    return DependencyPackageV1(ecosystem, name, version, locator, digest, license_name, (), True)


def _inventory(*packages: DependencyPackageV1):
    return dependency_inventory(*packages)


def _product() -> ProductTupleIdentityV1:
    return ProductTupleIdentityV1("a" * 64, "b" * 64, "0" * 64, "c" * 64, "d" * 64, ("Desktop",), "product-tuple-v1")


def _properties(value: dict[str, object]) -> dict[str, str]:
    return {item["name"]: item["value"] for item in value["properties"]}


def _metadata_property(document: dict[str, object], name: str) -> dict[str, str]:
    return next(item for item in document["metadata"]["properties"] if item["name"] == name)


def _blocks(case: unittest.TestCase, callback: object) -> None:
    with case.assertRaises(ReleaseFailure) as raised:
        callback()
    case.assertIs(raised.exception.code, FailureCodeV1.SBOM_INCOMPLETE)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
