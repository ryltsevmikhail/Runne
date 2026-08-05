import hashlib
from pathlib import Path

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.dependencies_cargo import cargo_packages
from scripts.release_v2.dependencies_common import fail, read, toml
from scripts.release_v2.dependencies_pnpm import pnpm_packages
from scripts.release_v2.dependency_specs import cargo_specs
from scripts.release_v2.dependencies_types import DependencyInventoryV1, DependencyPackageV1
from scripts.release_v2.dependencies_workspace import read_workspace_manifests
from scripts.release_v2.inventory import checksum_rows
from scripts.release_v2.model import ArtifactInventoryV2, BuildInputIdentityV2, FailureCodeV1, ReleaseFailure


def inventory_dependencies(cargo_lock: Path, pnpm_lock: Path, manifests: tuple[Path, ...], build: BuildInputIdentityV2, artifact_inventory: ArtifactInventoryV2 | None = None, bundled_components: tuple[str, ...] = ()) -> DependencyInventoryV1:
    try:
        cargo_raw, pnpm_raw = _inputs(cargo_lock, pnpm_lock, manifests, build)
        workspace = read_workspace_manifests(manifests)
        packages = cargo_packages(toml(cargo_raw), workspace, cargo_specs(manifests))
        packages.extend(pnpm_packages(pnpm_raw.decode("utf-8"), workspace))
        packages.extend(_bundled_packages(artifact_inventory, bundled_components))
        packages.sort(key=lambda item: item.reference.encode("utf-8"))
        _unique(packages)
        payload = {"schema_version": "dependency-inventory.v1", "packages": [_package_json(item) for item in packages]}
        return DependencyInventoryV1(tuple(packages), hashlib.sha256(canonical_json(payload)).hexdigest())
    except ReleaseFailure as error:
        if error.code is FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE:
            raise
        raise fail("dependency_metadata_invalid") from error
    except Exception as error:
        raise fail("dependency_input_invalid") from error


def _inputs(cargo: object, pnpm: object, manifests: object, build: object) -> tuple[bytes, bytes]:
    if not isinstance(cargo, Path) or not isinstance(pnpm, Path) or type(manifests) is not tuple or not all(isinstance(path, Path) for path in manifests) or type(build) is not BuildInputIdentityV2:
        raise fail("dependency_input_invalid")
    cargo_raw, pnpm_raw = read(cargo), read(pnpm)
    if hashlib.sha256(cargo_raw).hexdigest() != build.cargo_lock_sha256 or hashlib.sha256(pnpm_raw).hexdigest() != build.pnpm_lock_sha256:
        raise fail("dependency_lock_identity_mismatch")
    return cargo_raw, pnpm_raw


def _unique(packages: list[DependencyPackageV1]) -> None:
    references = [package.reference for package in packages]
    if len(set(references)) != len(references):
        raise fail("dependency_duplicate_lock")


def _package_json(package: DependencyPackageV1) -> dict[str, object]:
    return {"dependencies": list(package.dependencies), "direct": package.direct, "ecosystem": package.ecosystem, "license": package.declared_license, "lock_locator": package.lock_locator, "name": package.name, "source_digest": package.source_digest, "version": package.version}


def _bundled_packages(inventory: ArtifactInventoryV2 | None, components: tuple[str, ...]) -> list[DependencyPackageV1]:
    if inventory is None:
        if components:
            raise fail("bundled_inventory_missing")
        return []
    if type(components) is not tuple or not all(type(path) is str for path in components) or len(set(components)) != len(components):
        raise fail("bundled_components_invalid")
    try:
        checksum_rows(inventory)
    except ReleaseFailure as error:
        raise fail("bundled_inventory_invalid") from error
    entries = {entry.path: entry for entry in inventory.entries if entry.kind == "file" and entry.mode == "0755"}
    if set(components) != set(entries):
        raise fail("bundled_components_incomplete")
    return [DependencyPackageV1("bundled", path, entry.sha256, f"artifact:{path}", entry.sha256, None, (), True) for path, entry in entries.items()]
