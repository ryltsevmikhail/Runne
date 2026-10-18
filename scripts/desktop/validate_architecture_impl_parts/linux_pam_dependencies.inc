"""Fail-closed Linux PAM native adapter to FFI leaf dependency shape."""
from __future__ import annotations

LINUX_PAM_PACKAGE = "runne-linux-pam"
LINUX_PAM_CONSUMER = "runne-platform-desktop"
LINUX_PAM_TARGET = 'cfg(target_os = "linux")'
LINUX_PAM_DEPENDENCIES = {"libc": "^0.2", "zeroize": "=1.9.0"}
LINUX_PAM_METADATA_FIELDS = {
    "name", "source", "req", "kind", "rename", "optional",
    "uses_default_features", "features", "target", "registry",
}
ALLOWED_RUST_DEPENDENCIES[LINUX_PAM_CONSUMER].add(LINUX_PAM_PACKAGE)


def find_linux_pam_dependency_violations(packages: list[dict], root: Path) -> list[str]:
    """Validate this edge across all metadata, including unlisted consumers."""
    violations = []
    consumers = [package for package in packages if package.get("name") == LINUX_PAM_CONSUMER]
    if len(consumers) != 1:
        violations.append(f"{LINUX_PAM_CONSUMER} package is missing or duplicated")

    edges = [
        (package.get("name", "<unknown>"), dependency)
        for package in packages
        for dependency in package.get("dependencies", [])
        if dependency.get("name") == LINUX_PAM_PACKAGE
    ]
    if len(edges) != 1:
        violations.append(f"{LINUX_PAM_PACKAGE} must have exactly one metadata consumer")
    expected_path = (root.resolve() / "crates" / LINUX_PAM_PACKAGE).resolve()
    for owner, dependency in edges:
        if owner != LINUX_PAM_CONSUMER:
            violations.append(f"{owner} -> {LINUX_PAM_PACKAGE} is a forbidden consumer")
        path = dependency.get("path")
        path_matches = isinstance(path, str) and Path(path).resolve() == expected_path
        shape_matches = (
            LINUX_PAM_METADATA_FIELDS.issubset(dependency)
            and dependency.get("source") is None
            and dependency.get("req") == "*"
            and dependency.get("kind") is None
            and dependency.get("rename") is None
            and dependency.get("optional") is False
            and dependency.get("uses_default_features") is True
            and dependency.get("features") == []
            and dependency.get("target") == LINUX_PAM_TARGET
            and dependency.get("registry") is None
            and path_matches
        )
        if not shape_matches:
            violations.append(f"{owner} -> {LINUX_PAM_PACKAGE} has forbidden dependency shape")

    leaves = [package for package in packages if package.get("name") == LINUX_PAM_PACKAGE]
    if len(leaves) != 1:
        violations.append(f"{LINUX_PAM_PACKAGE} package is missing or duplicated")
    expected_manifest = expected_path / "Cargo.toml"
    for package in leaves:
        manifest = package.get("manifest_path")
        manifest_matches = (
            isinstance(manifest, str) and Path(manifest).resolve() == expected_manifest
        )
        if not manifest_matches:
            violations.append(f"{LINUX_PAM_PACKAGE} manifest_path is noncanonical")
        dependencies = package.get("dependencies", [])
        if not isinstance(dependencies, list) or len(dependencies) != len(LINUX_PAM_DEPENDENCIES):
            violations.append(f"{LINUX_PAM_PACKAGE} must have exactly two dependencies")
            continue
        observed = set()
        for dependency in dependencies:
            name = dependency.get("name", "<unnamed>")
            requirement = LINUX_PAM_DEPENDENCIES.get(name)
            if requirement is None:
                violations.append(f"{LINUX_PAM_PACKAGE} -> {name} is outside exact dependency allowlist")
                continue
            if name in observed:
                violations.append(f"{LINUX_PAM_PACKAGE} -> {name} is duplicated")
                continue
            observed.add(name)
            shape_matches = (
                LINUX_PAM_METADATA_FIELDS.issubset(dependency)
                and dependency.get("source") == CARGO_REGISTRY_SOURCE
                and dependency.get("req") == requirement
                and dependency.get("kind") is None
                and dependency.get("rename") is None
                and dependency.get("optional") is False
                and dependency.get("uses_default_features") is True
                and dependency.get("features") == []
                and dependency.get("target") is None
                and dependency.get("registry") is None
                and dependency.get("path") is None
            )
            if not shape_matches:
                violations.append(f"{LINUX_PAM_PACKAGE} -> {name} has forbidden dependency shape")
        for name in sorted(LINUX_PAM_DEPENDENCIES.keys() - observed):
            violations.append(f"{LINUX_PAM_PACKAGE} -> {name} exact dependency is missing")
    return sorted(violations)
