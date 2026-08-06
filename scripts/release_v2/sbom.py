import base64
import binascii
import hashlib
import json
import re
from urllib.parse import quote
from urllib.parse import urlsplit

from scripts.release_v2.canonical import canonical_json, validate_relative_path, validate_sha256
from scripts.release_v2.dependencies_types import DependencyInventoryV1, DependencyPackageV1
from scripts.release_v2.model import FailureCodeV1, ProductTupleIdentityV1, ReleaseFailure


_NAME = re.compile(r"[A-Za-z0-9_.-]+")
_SCOPED_NAME = re.compile(r"@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_VERSION = re.compile(r"[A-Za-z0-9+_.-]+")
_ROOT_REF = "pkg:generic/gocode-desktop@release-v2"


def build_sbom(inventory: DependencyInventoryV1, product: ProductTupleIdentityV1, *, structural_fixture: bool = False) -> bytes:
    try:
        _validate_fixture_mode(structural_fixture)
        _validate_inventory(inventory, structural_fixture)
        _validate_product(product)
        return canonical_json(_document(inventory, product))
    except ReleaseFailure:
        raise
    except Exception as error:
        raise _incomplete() from error


def bind_sbom(product: ProductTupleIdentityV1, raw: bytes) -> ProductTupleIdentityV1:
    try:
        _validate_product(product)
        if type(raw) is not bytes:
            raise _incomplete()
        return ProductTupleIdentityV1(
            product.build_input_sha256, product.artifact_inventory_sha256,
            hashlib.sha256(raw).hexdigest(), product.license_report_sha256,
            product.provenance_sha256, product.components, product.schema_revision,
        )
    except ReleaseFailure:
        raise
    except Exception as error:
        raise _incomplete() from error


def validate_sbom(raw: bytes, inventory: DependencyInventoryV1, product: ProductTupleIdentityV1, *, structural_fixture: bool = False) -> None:
    try:
        _validate_fixture_mode(structural_fixture)
        _validate_inventory(inventory, structural_fixture)
        _validate_product(product)
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != product.sbom_sha256:
            raise _incomplete()
        document = json.loads(raw.decode("utf-8"))
        if raw != canonical_json(document) or document != _document(inventory, product):
            raise _incomplete()
    except ReleaseFailure as error:
        if error.code is FailureCodeV1.SBOM_INCOMPLETE:
            raise
        raise _incomplete() from error
    except Exception as error:
        raise _incomplete() from error


def _document(inventory: DependencyInventoryV1, product: ProductTupleIdentityV1) -> dict[str, object]:
    components = [_root(product)] + [_component(package) for package in inventory.packages]
    components.sort(key=lambda item: item["bom-ref"].encode("utf-8"))
    refs = {package.reference: _purl(package) for package in inventory.packages}
    edges = [{"ref": _ROOT_REF, "dependsOn": sorted((refs[package.reference] for package in inventory.packages if package.direct), key=_bytes)}]
    edges.extend({"ref": refs[package.reference], "dependsOn": sorted((refs[reference] for reference in package.dependencies), key=_bytes)} for package in inventory.packages)
    edges.sort(key=lambda item: item["ref"].encode("utf-8"))
    root = next(item for item in components if item["bom-ref"] == _ROOT_REF)
    return {
        "bomFormat": "CycloneDX", "components": components, "dependencies": edges,
        "metadata": {"component": root, "properties": _properties(product), "tools": {"components": [{"name": "gocode-release-v2", "type": "application", "vendor": "GOCODE", "version": "1"}]}},
        "specVersion": "1.5", "version": 1,
    }


def _root(product: ProductTupleIdentityV1) -> dict[str, object]:
    return {"bom-ref": _ROOT_REF, "licenses": _licenses("LicenseRef-GOCODE-Proprietary"), "name": "GOCODE Desktop", "purl": _ROOT_REF, "type": "application", "version": "release-v2"}


def _component(package: DependencyPackageV1) -> dict[str, object]:
    result: dict[str, object] = {
        "bom-ref": _purl(package), "licenses": _licenses(package.declared_license), "name": package.name,
        "properties": _package_properties(package), "purl": _purl(package), "type": "library", "version": package.version,
    }
    result["hashes"] = _hashes(package)
    return result


def _properties(product: ProductTupleIdentityV1) -> list[dict[str, str]]:
    subject = hashlib.sha256(canonical_json({"artifact_inventory_sha256": product.artifact_inventory_sha256, "build_input_sha256": product.build_input_sha256, "schema_revision": product.schema_revision})).hexdigest()
    values = {
        "gocode:build-input-sha256": product.build_input_sha256,
        "gocode:candidate-sha256": product.artifact_inventory_sha256,
        "gocode:product-components-sha256": hashlib.sha256(canonical_json(product.components)).hexdigest(),
        "gocode:product-tuple-schema": product.schema_revision,
        "gocode:qualification-subject-sha256": subject,
        "gocode:schema": "cyclonedx-1.5", "gocode:tool": "gocode-release-v2",
    }
    return [{"name": name, "value": values[name]} for name in sorted(values, key=_bytes)]


def _package_properties(package: DependencyPackageV1) -> list[dict[str, str]]:
    values = {
        "gocode:direct-transitive": "DIRECT" if package.direct else "TRANSITIVE",
        "gocode:license-disposition": "UNKNOWN" if package.declared_license is None else "DECLARED",
        "gocode:lock-locator": package.lock_locator, "gocode:source-kind": package.ecosystem,
    }
    if package.ecosystem == "bundled":
        values["gocode:bundled-path"] = package.name
    return [{"name": name, "value": values[name]} for name in sorted(values, key=_bytes)]


def _licenses(value: str | None) -> list[dict[str, dict[str, str]]]:
    return [{"license": {"name": "UNKNOWN" if value is None else value}}]


def _hashes(package: DependencyPackageV1) -> list[dict[str, str]]:
    value = package.source_digest
    if re.fullmatch(r"[0-9a-f]{64}", value) and package.ecosystem != "pnpm":
        return [{"alg": "SHA-256", "content": value}]
    if package.ecosystem == "cargo" and re.fullmatch(r"[0-9a-f]{40}", value):
        return [{"alg": "SHA-1", "content": value}]
    if package.ecosystem == "pnpm" and package.lock_locator.startswith(("workspace:", "path:")) and re.fullmatch(r"[0-9a-f]{64}", value):
        return [{"alg": "SHA-256", "content": value}]
    if package.ecosystem == "pnpm" and value.startswith("sha512-"):
        encoded = value[7:]
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise _incomplete() from error
        if len(decoded) == 64 and base64.b64encode(decoded).decode("ascii") == encoded:
            return [{"alg": "SHA-512", "content": decoded.hex()}]
    raise _incomplete()


def _purl(package: DependencyPackageV1) -> str:
    if package.ecosystem == "cargo":
        return f"pkg:cargo/{quote(package.name, safe='-._~')}@{quote(package.version, safe='-._~')}"
    if package.ecosystem == "pnpm":
        return f"pkg:npm/{quote(package.name, safe='/-._~')}@{quote(package.version, safe='-._~')}"
    return f"pkg:generic/gocode-bundled/{quote(package.name, safe='/-._~')}@{quote(package.version, safe='-._~')}"


def _validate_inventory(inventory: object, structural_fixture: bool) -> None:
    if type(inventory) is not DependencyInventoryV1 or type(inventory.packages) is not tuple or not inventory.packages:
        raise _incomplete()
    packages = inventory.packages
    if not all(type(package) is DependencyPackageV1 for package in packages) or tuple(sorted(packages, key=lambda item: item.reference.encode("utf-8"))) != packages:
        raise _incomplete()
    references = {package.reference for package in packages}
    if len(references) != len(packages) or any(not _valid_package(package, references) for package in packages):
        raise _incomplete()
    if not structural_fixture and any(package.declared_license is None for package in packages):
        raise _incomplete()
    payload = {"schema_version": "dependency-inventory.v1", "packages": [_package_json(package) for package in packages]}
    if inventory.inventory_sha256 != hashlib.sha256(canonical_json(payload)).hexdigest():
        raise _incomplete()


def _valid_package(package: DependencyPackageV1, references: set[str]) -> bool:
    name = _bundled_name(package.name) if package.ecosystem == "bundled" else (_SCOPED_NAME.fullmatch(package.name) if package.ecosystem == "pnpm" and package.name.startswith("@") else _NAME.fullmatch(package.name))
    try:
        hashes = _hashes(package)
    except ReleaseFailure:
        hashes = []
    return bool(package.ecosystem in ("cargo", "pnpm", "bundled") and name and _VERSION.fullmatch(package.version) and _safe_locator(package.lock_locator) and (package.ecosystem != "bundled" or package.lock_locator == f"artifact:{package.name}") and hashes and (package.declared_license is None or _safe_license(package.declared_license)) and type(package.direct) is bool and type(package.dependencies) is tuple and tuple(sorted(package.dependencies, key=_bytes)) == package.dependencies and len(set(package.dependencies)) == len(package.dependencies) and set(package.dependencies) <= references)


def _validate_product(product: object) -> None:
    if type(product) is not ProductTupleIdentityV1 or type(product.components) is not tuple or not all(type(value) is str for value in product.components):
        raise _incomplete()
    try:
        for value in (product.build_input_sha256, product.artifact_inventory_sha256, product.sbom_sha256, product.license_report_sha256, product.provenance_sha256):
            validate_sha256(value)
        if not _safe_text(product.schema_revision):
            raise _incomplete()
    except ReleaseFailure as error:
        raise _incomplete() from error


def _package_json(package: DependencyPackageV1) -> dict[str, object]:
    return {"dependencies": list(package.dependencies), "direct": package.direct, "ecosystem": package.ecosystem, "license": package.declared_license, "lock_locator": package.lock_locator, "name": package.name, "source_digest": package.source_digest, "version": package.version}


def _safe_license(value: str) -> bool:
    return _safe_text(value) and not any(marker in value for marker in ("/", ":", "@"))


def _safe_text(value: object) -> bool:
    return type(value) is str and bool(value) and value.isascii() and not any(character.isspace() for character in value) and "://" not in value


def _bundled_name(value: object) -> bool:
    try:
        return validate_relative_path(value) == value
    except ReleaseFailure:
        return False


def _safe_locator(value: object) -> bool:
    if type(value) is not str or not value or not value.isascii() or any(character.isspace() for character in value) or "?" in value or "#" in value:
        return False
    if "://" not in value:
        return True
    parsed = urlsplit(value)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc) and parsed.username is None and parsed.password is None and "@" not in parsed.netloc


def _validate_fixture_mode(value: object) -> None:
    if type(value) is not bool:
        raise _incomplete()


def _bytes(value: str) -> bytes:
    return value.encode("utf-8")


def _incomplete() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.SBOM_INCOMPLETE, "sbom_incomplete")
