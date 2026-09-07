"""Fail-closed dependency policy for the credential service core."""
from __future__ import annotations

CREDENTIAL_SERVICE_CORE_PACKAGE = "runne-credential-service-core"
CARGO_REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
ALLOWED_RUST_DEPENDENCIES[CREDENTIAL_SERVICE_CORE_PACKAGE] = {
    "runne-api",
    "runne-provider",
}
CREDENTIAL_SERVICE_CORE_DEPENDENCIES = {
    ("normal", "rand"): ("=0.8.7", (), False, None, None, True, ("registry",)),
    ("normal", "runne-api"): ("*", (), False, None, None, True, ("path", "runne-api")),
    ("normal", "runne-provider"): ("*", (), False, None, None, True, ("path", "runne-provider")),
    ("normal", "subtle"): ("=2.6.1", (), False, None, None, True, ("registry",)),
    ("normal", "zeroize"): ("=1.9.0", (), False, None, None, True, ("registry",)),
    ("dev", "runne-provider"): ("*", ("test-support",), False, None, None, True, ("path", "runne-provider")),
}


def find_credential_service_core_dependency_violations(
    packages: list[dict],
) -> list[str]:
    """Require the complete dependency shape; every unlisted edge fails closed."""
    violations = []
    package_found = False
    for package in packages:
        if package.get("name") != CREDENTIAL_SERVICE_CORE_PACKAGE:
            continue
        package_found = True
        crates_directory = _credential_service_core_crates_directory(
            package.get("manifest_path")
        )
        if crates_directory is None:
            violations.append(
                f"{CREDENTIAL_SERVICE_CORE_PACKAGE} manifest_path is missing or noncanonical"
            )
        observed = set()
        for dependency in package.get("dependencies", []):
            name = dependency.get("name", "")
            kind = dependency.get("kind") or "normal"
            key = (kind, name)
            shape = (
                dependency.get("req"),
                tuple(sorted(dependency.get("features", []))),
                dependency.get("optional", False),
                dependency.get("rename"),
                dependency.get("target"),
                dependency.get("uses_default_features", True),
                _credential_service_core_dependency_location(
                    dependency, crates_directory
                ),
            )
            expected = CREDENTIAL_SERVICE_CORE_DEPENDENCIES.get(key)
            if expected is None:
                violations.append(
                    f"{CREDENTIAL_SERVICE_CORE_PACKAGE} -> {name} ({kind}) is outside exact dependency allowlist"
                )
            elif key in observed:
                violations.append(
                    f"{CREDENTIAL_SERVICE_CORE_PACKAGE} -> {name} ({kind}) is duplicated"
                )
            elif shape != expected:
                violations.append(
                    f"{CREDENTIAL_SERVICE_CORE_PACKAGE} -> {name} ({kind}) has forbidden dependency shape"
                )
            observed.add(key)
        for kind, name in sorted(CREDENTIAL_SERVICE_CORE_DEPENDENCIES.keys() - observed):
            violations.append(
                f"{CREDENTIAL_SERVICE_CORE_PACKAGE} -> {name} ({kind}) exact dependency is missing"
            )
    if not package_found:
        violations.append(
            f"{CREDENTIAL_SERVICE_CORE_PACKAGE} package is missing from workspace metadata"
        )
    return sorted(violations)


def _credential_service_core_crates_directory(manifest_path: object) -> Path | None:
    if not isinstance(manifest_path, str):
        return None
    manifest = Path(manifest_path).resolve()
    package = manifest.parent
    if manifest.name != "Cargo.toml" or package.name != CREDENTIAL_SERVICE_CORE_PACKAGE:
        return None
    return package.parent


def _credential_service_core_dependency_location(
    dependency: dict, crates_directory: Path | None
) -> tuple:
    source = dependency.get("source")
    path = dependency.get("path")
    registry = dependency.get("registry")
    if source == CARGO_REGISTRY_SOURCE and path is None and registry is None:
        return ("registry",)
    name = dependency.get("name", "")
    if source is None and registry is None and path and crates_directory is not None:
        expected = (crates_directory / name).resolve()
        if Path(path).resolve() == expected:
            return ("path", name)
    return ("invalid", source, path, registry)
