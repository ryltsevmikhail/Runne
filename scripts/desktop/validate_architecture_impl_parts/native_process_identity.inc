"""Target-scoped native process identity dependency checks."""

MACOS_PROCESS_IDENTITY_PACKAGE = "runne-macos-process-identity"
MACOS_PROCESS_IDENTITY_TARGET = 'cfg(target_os = "macos")'
MACOS_PROCESS_IDENTITY_VIOLATION = (
    "runne-platform-desktop must depend on "
    "runne-macos-process-identity only through "
    'cfg(target_os = "macos")'
)

ALLOWED_RUST_DEPENDENCIES["runne-platform-desktop"].add(
    MACOS_PROCESS_IDENTITY_PACKAGE
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
            if package_name != "runne-platform-desktop":
                violations.append(
                    f"{package_name} -> {MACOS_PROCESS_IDENTITY_PACKAGE} is forbidden"
                )
            elif dependency.get("target") != MACOS_PROCESS_IDENTITY_TARGET:
                violations.append(MACOS_PROCESS_IDENTITY_VIOLATION)
    return violations
