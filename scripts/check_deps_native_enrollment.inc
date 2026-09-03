"""Exact consumers of native enrollment authority."""

NATIVE_PROBE_CONSUMER = "runne-daemon"
NATIVE_PROBE_FEATURE = "persistent-reference-probe"
NATIVE_MACOS_TARGET = 'cfg(target_os = "macos")'
NATIVE_PROBE_FEATURE_EDGES = {
    "test-support",
    "desktop-protected",
    "runne-macos-keychain-acl/persistent-reference-probe",
    "dep:runne-native-enrollment-authority",
    "runne-native-enrollment-authority/local-native-enrollment-test",
}


def native_enrollment_authority_consumer_errors(packages: list[dict]) -> list[str]:
    """Keep admission on writer edges plus the closed local probe fixture."""
    consumers = sorted(
        package["name"]
        for package in packages
        if package["name"] not in NATIVE_ENROLLMENT_AUTHORITY_CONSUMERS
        and any(
            dependency["name"] == NATIVE_ENROLLMENT_AUTHORITY
            and dependency.get("kind") != "dev"
            and not _exact_daemon_probe_edge(package, dependency)
            for dependency in package.get("dependencies", [])
        )
    )
    if not consumers:
        return []
    return [
        "FAIL: runne-native-enrollment-authority has forbidden "
        f"production consumers: {consumers}"
    ]


def _exact_daemon_probe_edge(package: dict, dependency: dict) -> bool:
    features = package.get("features", {}).get(NATIVE_PROBE_FEATURE)
    return (
        package.get("name") == NATIVE_PROBE_CONSUMER
        and dependency.get("kind") is None
        and dependency.get("target") == NATIVE_MACOS_TARGET
        and dependency.get("optional") is True
        and dependency.get("rename") is None
        and dependency.get("source") is None
        and set(features or ()) == NATIVE_PROBE_FEATURE_EDGES
    )
