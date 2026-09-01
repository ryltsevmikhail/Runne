"""Target-scoped native process identity dependency checks."""

MACOS_PROCESS_IDENTITY_PACKAGE = "runne-macos-process-identity"
MACOS_PROCESS_IDENTITY_TARGET = 'cfg(target_os = "macos")'
NATIVE_ENROLLMENT_AUTHORITY_PACKAGE = "runne-native-enrollment-authority"
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
