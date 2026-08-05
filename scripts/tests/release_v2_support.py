import hashlib

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.dependencies_types import DependencyInventoryV1, DependencyPackageV1


def fixture_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def fixture_json(value: object) -> bytes:
    return canonical_json(value)


def dependency_inventory(*packages: DependencyPackageV1) -> DependencyInventoryV1:
    ordered = tuple(sorted(packages, key=lambda item: item.reference.encode("utf-8")))
    rows = [
        {"dependencies": list(item.dependencies), "direct": item.direct, "ecosystem": item.ecosystem,
         "license": item.declared_license, "lock_locator": item.lock_locator, "name": item.name,
         "source_digest": item.source_digest, "version": item.version}
        for item in ordered
    ]
    return DependencyInventoryV1(ordered, hashlib.sha256(canonical_json({"schema_version": "dependency-inventory.v1", "packages": rows})).hexdigest())
