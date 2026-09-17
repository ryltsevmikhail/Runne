"""The installed root bootstrap issuer is an executable, never an application library."""
ROOT_SERVICE_PACKAGE = "runne-qualification-root-service"
ROOT_SERVICE_INTERNAL = {
    "runne-api", "runne-macos-xpc", "runne-native-qualification",
    "runne-qualification-bootstrap-policy", "runne-qualification-runner",
    "runne-macos-file-security",
}
ALLOWED_RUST_DEPENDENCIES[ROOT_SERVICE_PACKAGE] = ROOT_SERVICE_INTERNAL


def find_qualification_root_service_violations(packages: list[dict], root: Path) -> list[str]:
    rows = [row for row in packages if row.get("name") == ROOT_SERVICE_PACKAGE]
    if len(rows) != 1:
        return ["qualification root service is missing or ambiguous"]
    row = rows[0]
    expected_path = root.resolve() / "crates" / ROOT_SERVICE_PACKAGE
    expected = {name: ("*", (), None) for name in ROOT_SERVICE_INTERNAL}
    expected["runne-macos-file-security"] = ("*", (), 'cfg(target_os = "macos")')
    expected.update({
        "base64": ("=0.22.1", (), None), "ed25519-dalek": ("=2.1.1", (), None),
        "hex": ("^0.4", (), None), "rand": ("=0.8.7", (), None),
        "serde": ("=1.0.229", ("derive",), None), "serde_json": ("=1.0.151", (), None),
        "sha2": ("=0.10.8", (), None), "zeroize": ("=1.9.0", (), None),
        "rustix": ("=1.1.4", ("fs", "process"), 'cfg(target_os = "macos")'),
    })
    errors = []
    if Path(row.get("manifest_path", "")).resolve() != expected_path / "Cargo.toml" or row.get("features", {}):
        errors.append("qualification root service manifest or features differ")
    targets = row.get("targets", [])
    if len(targets) != 1 or targets[0].get("kind") != ["bin"] or Path(targets[0].get("src_path", "")).resolve() != expected_path / "src/main.rs":
        errors.append("qualification root service must remain one binary")
    if any(dep.get("name") == ROOT_SERVICE_PACKAGE for owner in packages for dep in owner.get("dependencies", [])):
        errors.append("qualification root service must not enter application dependencies")
    observed = set()
    for dep in row.get("dependencies", []):
        if dep.get("kind") == "dev":
            if dep.get("name") != "tempfile" or dep.get("features", []):
                errors.append("qualification root service dev dependency differs")
            continue
        name = dep.get("name")
        path = dep.get("path")
        source_ok = (dep.get("source") is None and isinstance(path, str)
                     and Path(path).resolve() == root.resolve() / "crates" / name
                     if name in ROOT_SERVICE_INTERNAL else
                     dep.get("source") == CARGO_REGISTRY_SOURCE and path is None)
        shape = (dep.get("req"), tuple(sorted(dep.get("features", []))), dep.get("target"))
        if (name in observed or expected.get(name) != shape or not source_ok
                or dep.get("kind") is not None or dep.get("optional", False)
                or not dep.get("uses_default_features", True) or dep.get("rename") is not None
                or dep.get("registry") is not None):
            errors.append("qualification root service dependency has forbidden shape")
        observed.add(name)
    if observed != set(expected):
        errors.append("qualification root service dependencies differ")
    return sorted(set(errors))
