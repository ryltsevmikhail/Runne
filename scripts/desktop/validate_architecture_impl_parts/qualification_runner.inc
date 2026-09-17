"""Keep durable runner persistence outside application/runtime ownership."""
QUALIFICATION_RUNNER_PACKAGE = "runne-qualification-runner"
ALLOWED_RUST_DEPENDENCIES[QUALIFICATION_RUNNER_PACKAGE] = {NATIVE_QUALIFICATION_PACKAGE, "runne-api", "runne-sqlite-native-identity", "runne-sqlite-handle-identity", "runne-macos-file-security"}


def find_qualification_runner_dependency_violations(packages: list[dict]) -> list[str]:
    rows = [row for row in packages if row.get("name") == QUALIFICATION_RUNNER_PACKAGE]
    if len(rows) != 1:
        return ["qualification runner package is missing or ambiguous"]
    package = rows[0]
    expected = {
        "runne-api": ("*", (), True, None),
        "runne-native-qualification": ("*", (), True, None),
        "runne-sqlite-native-identity": ("*", (), True, None),
        "runne-sqlite-handle-identity": ("*", (), True, None),
        "runne-macos-file-security": ("*", (), True, 'cfg(target_os = "macos")'),
        "rusqlite": ("=0.34.0", ("bundled",), True, None),
        "rustix": ("=1.1.4", ("fs", "process"), True, "cfg(unix)"),
    }
    native = [row for row in packages if row.get("name") == NATIVE_QUALIFICATION_PACKAGE]
    native_path = Path(native[0]["manifest_path"]).parent.resolve() if len(native) == 1 and isinstance(native[0].get("manifest_path"), str) else None
    violations = []
    if any(dep.get("name") == QUALIFICATION_RUNNER_PACKAGE for owner in packages if owner.get("name") != "runne-qualification-root-service" for dep in owner.get("dependencies", [])):
        violations.append("qualification runner persistence must not enter application dependencies")
    if package.get("features", {}):
        violations.append("qualification runner must not expose feature bypasses")
    observed = set()
    for dependency in package.get("dependencies", []):
        kind = dependency.get("kind") or "normal"
        name = dependency.get("name")
        if kind == "dev":
            continue  # Native qualification's exact dev edge is checked separately.
        shape = (dependency.get("req"), tuple(sorted(dependency.get("features", []))), dependency.get("uses_default_features", True), dependency.get("target"))
        path = dependency.get("path")
        source_ok = (
            dependency.get("source") is None and isinstance(path, str)
            and native_path is not None and Path(path).resolve() == native_path.parent / name
        ) if name in ALLOWED_RUST_DEPENDENCIES[QUALIFICATION_RUNNER_PACKAGE] else (
            dependency.get("source") == CARGO_REGISTRY_SOURCE and path is None
        )
        if kind != "normal" or name in observed or expected.get(name) != shape or not source_ok or dependency.get("registry") is not None or dependency.get("rename") is not None or dependency.get("optional", False):
            violations.append("qualification runner dependency has forbidden shape")
        observed.add(name)
    if observed != set(expected):
        violations.append("qualification runner production dependencies differ")
    return sorted(set(violations))
