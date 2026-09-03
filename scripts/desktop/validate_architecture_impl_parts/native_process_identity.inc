"""Target-scoped native process identity dependency checks."""
from __future__ import annotations

MACOS_PROCESS_IDENTITY_PACKAGE = "runne-macos-process-identity"
MACOS_PROCESS_IDENTITY_TARGET = 'cfg(target_os = "macos")'
NATIVE_ENROLLMENT_AUTHORITY_PACKAGE = "runne-native-enrollment-authority"
CLI_PACKAGE = "runne-cli"
RUSTIX_PACKAGE = "rustix"
CRATES_IO_REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
MACOS_PROCESS_IDENTITY_CONSUMERS = {
    "runne-platform-desktop",
    NATIVE_ENROLLMENT_AUTHORITY_PACKAGE,
}

ALLOWED_RUST_DEPENDENCIES["runne-platform-desktop"].add(
    MACOS_PROCESS_IDENTITY_PACKAGE
)
ALLOWED_RUST_DEPENDENCIES[NATIVE_ENROLLMENT_AUTHORITY_PACKAGE] = {
    "runne-api",
    MACOS_PROCESS_IDENTITY_PACKAGE,
    "runne-provider",
}
ALLOWED_RUST_DEPENDENCIES["runne-secure-store"].add(
    NATIVE_ENROLLMENT_AUTHORITY_PACKAGE
)


def find_macos_process_identity_dependency_violations(
    packages: list[dict],
) -> list[str]:
    """Allow the audited process bridge only on the macOS target edge."""
    violations = []
    for package in packages:
        package_name = package.get("name")
        for dependency in package.get("dependencies", []):
            if dependency.get("name") != MACOS_PROCESS_IDENTITY_PACKAGE:
                continue
            if package_name not in MACOS_PROCESS_IDENTITY_CONSUMERS:
                violations.append(
                    f"{package_name} -> {MACOS_PROCESS_IDENTITY_PACKAGE} is forbidden"
                )
            elif dependency.get("target") != MACOS_PROCESS_IDENTITY_TARGET:
                violations.append(
                    f"{package_name} must depend on {MACOS_PROCESS_IDENTITY_PACKAGE} "
                    f"only through {MACOS_PROCESS_IDENTITY_TARGET}"
                )
    return violations


def find_native_writer_bootstrap_dependency_violations(
    packages: list[dict],
) -> list[str]:
    """Require the exact authority and CLI edges for native writer ingress."""
    by_name = {package.get("name"): package for package in packages}
    violations = []
    authority = by_name.get(NATIVE_ENROLLMENT_AUTHORITY_PACKAGE, {})
    authority_normal = [
        dependency
        for dependency in authority.get("dependencies", [])
        if dependency.get("kind") is None
    ]
    expected_authority = {
        "runne-api": (
            None,
            MACOS_PROCESS_IDENTITY_TARGET,
            "*",
            (),
            "local",
            _package_directory(by_name, "runne-api"),
        ),
        "runne-provider": (
            None,
            None,
            "*",
            (),
            "local",
            _package_directory(by_name, "runne-provider"),
        ),
        MACOS_PROCESS_IDENTITY_PACKAGE: (
            None,
            MACOS_PROCESS_IDENTITY_TARGET,
            "*",
            (),
            "local",
            _package_directory(by_name, MACOS_PROCESS_IDENTITY_PACKAGE),
        ),
    }
    violations += _exact_dependencies(
        NATIVE_ENROLLMENT_AUTHORITY_PACKAGE,
        authority_normal,
        expected_authority,
    )

    cli = by_name.get(CLI_PACKAGE, {})
    relevant_cli = [
        dependency
        for dependency in cli.get("dependencies", [])
        if dependency.get("name")
        in {
            NATIVE_ENROLLMENT_AUTHORITY_PACKAGE,
            MACOS_PROCESS_IDENTITY_PACKAGE,
            RUSTIX_PACKAGE,
        }
    ]
    expected_cli = {
        NATIVE_ENROLLMENT_AUTHORITY_PACKAGE: (
            None,
            MACOS_PROCESS_IDENTITY_TARGET,
            "*",
            (),
            "local",
            _package_directory(by_name, NATIVE_ENROLLMENT_AUTHORITY_PACKAGE),
        ),
        RUSTIX_PACKAGE: (
            "dev",
            MACOS_PROCESS_IDENTITY_TARGET,
            "=1.1.4",
            ("net", "pipe"),
            "registry",
            None,
        ),
    }
    violations += _exact_dependencies(CLI_PACKAGE, relevant_cli, expected_cli)
    return violations


def _exact_dependencies(
    package: str,
    actual: list[dict],
    expected: dict[str, tuple],
) -> list[str]:
    violations = []
    for name, shape in expected.items():
        matches = [dependency for dependency in actual if dependency.get("name") == name]
        if len(matches) != 1 or not _dependency_has_shape(matches[0], *shape):
            violations.append(f"{package} must have one exact dependency edge to {name}")
    unexpected = sorted(
        dependency.get("name", "<unnamed>")
        for dependency in actual
        if dependency.get("name") not in expected
    )
    for name in unexpected:
        violations.append(f"{package} has forbidden native writer dependency {name}")
    return violations


def _dependency_has_shape(
    dependency: dict,
    kind: str | None,
    target: str | None,
    requirement: str,
    features: tuple[str, ...],
    source_kind: str,
    expected_path: str | None,
) -> bool:
    return (
        dependency.get("kind") == kind
        and dependency.get("target") == target
        and dependency.get("req") == requirement
        and tuple(sorted(dependency.get("features", []))) == tuple(sorted(features))
        and dependency.get("rename") is None
        and dependency.get("optional") is False
        and dependency.get("uses_default_features") is True
        and _dependency_source_is_exact(dependency, source_kind, expected_path)
    )


def _dependency_source_is_exact(
    dependency: dict,
    source_kind: str,
    expected_path: str | None,
) -> bool:
    if source_kind == "local":
        path = dependency.get("path")
        return (
            dependency.get("source") is None
            and expected_path is not None
            and isinstance(path, str)
            and str(Path(path).resolve()) == expected_path
        )
    source = dependency.get("source")
    return (
        source_kind == "registry"
        and isinstance(source, str)
        and source == CRATES_IO_REGISTRY_SOURCE
        and dependency.get("path") is None
    )


def _package_directory(packages: dict[str, dict], name: str) -> str | None:
    manifest = packages.get(name, {}).get("manifest_path")
    if not isinstance(manifest, str):
        return None
    return str(Path(manifest).resolve().parent)
