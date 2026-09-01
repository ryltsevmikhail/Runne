MACOS_PROCESS_IDENTITY_PACKAGE = "runne-macos-process-identity"


def macos_process_identity_dependency_errors(packages: list[dict]) -> list[str]:
    """Require the low-level crate's complete production dependency set."""
    package = next(
        (
            row
            for row in packages
            if row.get("name") == MACOS_PROCESS_IDENTITY_PACKAGE
        ),
        {},
    )
    actual = {
        dependency.get("name")
        for dependency in package.get("dependencies", [])
        if dependency.get("kind") != "dev"
    }
    expected = POLICIES[MACOS_PROCESS_IDENTITY_PACKAGE]
    if actual == expected:
        return []
    return [
        "FAIL: runne-macos-process-identity production dependencies must be exact; "
        f"expected {sorted(expected)}, found {sorted(actual)}"
    ]
