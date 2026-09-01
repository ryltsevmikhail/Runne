"""Exact low-level macOS process-observation dependency declaration."""
from __future__ import annotations

MACOS_IDENTITY_EXACT_DEPENDENCIES = {
    "core-foundation": ("=0.10.1", (), True, "registry"),
    "libc": ("^0.2", (), True, "registry"),
    "nix": ("=0.31.3", ("fs", "poll", "socket"), False, "registry"),
    "runne-api": ("*", (), True, "local"),
    "runne-provider": ("*", (), True, "local"),
    "security-framework": ("=3.7.0", ("OSX_10_15",), True, "registry"),
    "security-framework-sys": ("=2.17.0", (), True, "registry"),
    "sha2": ("=0.10.8", (), True, "registry"),
}


def find_macos_process_identity_crate_dependency_violations(
    packages: list[dict],
) -> list[str]:
    """Require one exact target-macOS edge for every low-level dependency."""
    by_name = {package.get("name"): package for package in packages}
    package = by_name.get(MACOS_PROCESS_IDENTITY_PACKAGE, {})
    actual = [
        dependency
        for dependency in package.get("dependencies", [])
        if dependency.get("kind") is None
    ]
    violations = []
    for name, (requirement, features, defaults, source_kind) in (
        MACOS_IDENTITY_EXACT_DEPENDENCIES.items()
    ):
        matches = [dependency for dependency in actual if dependency.get("name") == name]
        expected_path = (
            _package_directory(by_name, name) if source_kind == "local" else None
        )
        if len(matches) != 1 or not _macos_identity_dependency_has_shape(
            matches[0], requirement, features, defaults, source_kind, expected_path
        ):
            violations.append(
                f"{MACOS_PROCESS_IDENTITY_PACKAGE} must have one exact dependency edge to {name}"
            )
    for dependency in actual:
        name = dependency.get("name", "<unnamed>")
        if name not in MACOS_IDENTITY_EXACT_DEPENDENCIES:
            violations.append(
                f"{MACOS_PROCESS_IDENTITY_PACKAGE} has forbidden dependency {name}"
            )
    return violations


def _macos_identity_dependency_has_shape(
    dependency: dict,
    requirement: str,
    features: tuple[str, ...],
    defaults: bool,
    source_kind: str,
    expected_path: str | None,
) -> bool:
    return (
        dependency.get("kind") is None
        and dependency.get("target") == MACOS_PROCESS_IDENTITY_TARGET
        and dependency.get("req") == requirement
        and tuple(sorted(dependency.get("features", []))) == tuple(sorted(features))
        and dependency.get("rename") is None
        and dependency.get("optional") is False
        and dependency.get("uses_default_features") is defaults
        and _dependency_source_is_exact(dependency, source_kind, expected_path)
    )
