"""Keep shared bootstrap policy reads outside runtime and native transport."""
BOOTSTRAP_POLICY_PACKAGE = "runne-qualification-bootstrap-policy"
ALLOWED_RUST_DEPENDENCIES[BOOTSTRAP_POLICY_PACKAGE] = {"runne-api", "runne-macos-file-security"}
ALLOWED_RUST_DEPENDENCIES["runne-macos-file-security"] = set()


def find_bootstrap_policy_dependency_violations(packages: list[dict], root: Path) -> list[str]:
    rows = [row for row in packages if row.get("name") == BOOTSTRAP_POLICY_PACKAGE]
    if len(rows) != 1:
        return ["bootstrap policy package is missing or ambiguous"]
    package = rows[0]
    expected = {
        "runne-api": ("*", (), True, None),
        "runne-macos-file-security": ("*", (), True, 'cfg(target_os = "macos")'),
        "serde": ("=1.0.229", ("derive",), True, None),
        "serde_json": ("=1.0.151", (), True, None),
        "sha2": ("=0.10.8", (), True, None),
        "hex": ("^0.4", (), True, None),
        "rustix": ("=1.1.4", ("fs",), True, 'cfg(target_os = "macos")'),
    }
    violations = []
    expected_manifest = root.resolve() / "crates" / BOOTSTRAP_POLICY_PACKAGE / "Cargo.toml"
    if Path(package.get("manifest_path", "")).resolve() != expected_manifest:
        violations.append("bootstrap policy manifest is noncanonical")
    if package.get("features", {}):
        violations.append("bootstrap policy must not expose feature bypasses")
    observed = set()
    for dependency in package.get("dependencies", []):
        kind = dependency.get("kind") or "normal"
        if kind == "dev":
            continue
        name = dependency.get("name")
        shape = (dependency.get("req"), tuple(sorted(dependency.get("features", []))),
                 dependency.get("uses_default_features", True), dependency.get("target"))
        path = dependency.get("path")
        source_ok = (
            dependency.get("source") is None and isinstance(path, str)
            and Path(path).resolve() == root.resolve() / "crates" / name
        ) if name in ALLOWED_RUST_DEPENDENCIES[BOOTSTRAP_POLICY_PACKAGE] else (
            dependency.get("source") == CARGO_REGISTRY_SOURCE and path is None
        )
        if (kind != "normal" or name in observed or expected.get(name) != shape
                or not source_ok or dependency.get("registry") is not None
                or dependency.get("rename") is not None or dependency.get("optional", False)):
            violations.append("bootstrap policy dependency has forbidden shape")
        observed.add(name)
    if observed != set(expected):
        violations.append("bootstrap policy production dependencies differ")
    return sorted(set(violations))


def find_macos_file_security_dependency_violations(packages: list[dict], root: Path) -> list[str]:
    rows = [row for row in packages if row.get("name") == "runne-macos-file-security"]
    if len(rows) != 1:
        return ["macOS file security adapter is missing or ambiguous"]
    row = rows[0]
    expected = root.resolve() / "crates/runne-macos-file-security/Cargo.toml"
    if Path(row.get("manifest_path", "")).resolve() != expected or row.get("features", {}):
        return ["macOS file security adapter manifest or features differ"]
    dependencies = [dep for dep in row.get("dependencies", []) if dep.get("kind") != "dev"]
    if len(dependencies) != 1:
        return ["macOS file security adapter dependencies differ"]
    dep = dependencies[0]
    if (dep.get("name") != "cc" or dep.get("req") != "=1.4.0"
            or dep.get("kind") != "build" or dep.get("features", [])
            or dep.get("target") is not None or dep.get("path") is not None
            or dep.get("source") != CARGO_REGISTRY_SOURCE
            or dep.get("uses_default_features", True) is not True
            or dep.get("optional", False) or dep.get("rename") is not None
            or dep.get("registry") is not None):
        return ["macOS file security adapter dependency has forbidden shape"]
    return []
