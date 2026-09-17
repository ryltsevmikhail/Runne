"""Fail-closed dependency and source boundary for the macOS XPC adapter."""
from __future__ import annotations

MACOS_XPC_PACKAGE = "runne-macos-xpc"
MACOS_XPC_TARGET = 'cfg(target_os = "macos")'
ALLOWED_RUST_DEPENDENCIES[MACOS_XPC_PACKAGE] = {"runne-platform-ports"}
MACOS_XPC_DEPENDENCIES = {
    "runne-platform-ports": (None, "*", (), True, None, "path"),
    "rand": (None, "=0.8.7", (), True, None, "registry"),
    "zeroize": (None, "=1.9.0", (), True, None, "registry"),
    "block2": (None, "=0.6.2", (), True, MACOS_XPC_TARGET, "registry"),
    "objc2": (None, "=0.6.4", ("exception",), True, MACOS_XPC_TARGET, "registry"),
    "objc2-foundation": (
        None,
        "=0.3.2",
        ("NSData", "NSError", "NSObject", "NSString", "NSXPCConnection", "block2", "libc", "std"),
        False,
        MACOS_XPC_TARGET,
        "registry",
    ),
    "objc2-service-management": (
        None,
        "=0.3.2",
        ("SMAppService", "objc2", "objc2-foundation", "std"),
        False,
        MACOS_XPC_TARGET,
        "registry",
    ),
    "libc": (None, "^0.2", (), True, MACOS_XPC_TARGET, "registry"),
    "tokio": (None, "^1", ("full",), True, MACOS_XPC_TARGET, "registry"),
    "cc": ("build", "=1.4.0", (), True, None, "registry"),
}
MACOS_XPC_NATIVE_MARKERS = re.compile(
    r"\b(?:NSXPC\w*|SMAppService\w*)\b|Runne(?:CredentialService|QualificationRunner)XpcProtocolV1|exchange:reply:"
)
def find_macos_xpc_dependency_violations(
    packages: list[dict], root: Path
) -> list[str]:
    """Require one exact, target-scoped dependency set for the adapter."""
    matches = [package for package in packages if package.get("name") == MACOS_XPC_PACKAGE]
    if len(matches) != 1:
        return [f"{MACOS_XPC_PACKAGE} package is missing or duplicated"]
    package = matches[0]
    manifest = package.get("manifest_path")
    crates_directory = root.resolve() / "crates"
    expected_manifest = crates_directory / MACOS_XPC_PACKAGE / "Cargo.toml"
    if isinstance(manifest, str):
        manifest_path = Path(manifest).resolve()
    else:
        manifest_path = None
    violations = []
    if manifest_path != expected_manifest:
        violations.append(f"{MACOS_XPC_PACKAGE} manifest_path is noncanonical")
    observed = set()
    for dependency in package.get("dependencies", []):
        name = dependency.get("name", "<unnamed>")
        expected = MACOS_XPC_DEPENDENCIES.get(name)
        if expected is None or name in observed:
            violations.append(f"{MACOS_XPC_PACKAGE} -> {name} is outside exact dependency allowlist")
        else:
            kind, requirement, features, defaults, target, location = expected
            exact_path = (
                crates_directory / name
                if location == "path"
                else None
            )
            source_ok = (
                dependency.get("source") == CRATES_IO_REGISTRY_SOURCE
                and dependency.get("path") is None
                if location == "registry"
                else dependency.get("source") is None
                and isinstance(dependency.get("path"), str)
                and Path(dependency["path"]).resolve() == exact_path
            )
            shape_ok = (
                dependency.get("kind") == kind
                and dependency.get("req") == requirement
                and tuple(sorted(dependency.get("features", []))) == tuple(sorted(features))
                and dependency.get("uses_default_features", True) is defaults
                and dependency.get("target") == target
                and dependency.get("optional", False) is False
                and dependency.get("rename") is None
                and dependency.get("registry") is None
                and source_ok
            )
            if not shape_ok:
                violations.append(f"{MACOS_XPC_PACKAGE} -> {name} has forbidden dependency shape")
        observed.add(name)
    for name in sorted(MACOS_XPC_DEPENDENCIES.keys() - observed):
        violations.append(f"{MACOS_XPC_PACKAGE} -> {name} exact dependency is missing")
    return sorted(violations)


def find_macos_xpc_source_violations(root: Path) -> list[str]:
    """Keep native symbols private to the bounded adapter and safe Rust API."""
    adapter = root / "crates" / MACOS_XPC_PACKAGE
    manifest = adapter / "Cargo.toml"
    sources = adapter / "src"
    if not manifest.exists() or not sources.exists():
        return [f"crates/{MACOS_XPC_PACKAGE} source boundary is missing"]
    violations = []
    manifest_text = manifest.read_text(encoding="utf-8")
    if not re.search(r'(?m)^\[lints\.rust\]\s*\nunsafe_code\s*=\s*"allow"\s*$', manifest_text):
        violations.append(f"{MACOS_XPC_PACKAGE} must isolate unsafe_code = allow")
    production_sources = [adapter / "build.rs"] + sorted(sources.rglob("*.rs"))
    production_sources += sorted(sources.rglob("*.m")) + sorted(sources.rglob("*.mm"))
    source_texts = {
        path: path.read_text(encoding="utf-8")
        for path in production_sources
        if path.exists()
    }
    public_generators = set()
    for path, text in source_texts.items():
        if path.suffix == ".rs":
            public_generators.update(rust_public_generating_macros(text))
    for path in production_sources:
        if not path.exists():
            continue
        text = source_texts[path]
        relative = path.relative_to(root).as_posix()
        if len(text.splitlines()) > 300:
            violations.append(f"{relative} exceeds the 300-line native adapter limit")
        public_foundation = path.suffix == ".rs" and rust_public_api_exposes_foundation(
            text, public_generators
        )
        if public_foundation:
            violations.append(f"{relative} exposes a Foundation type through public Rust API")
    scan_roots = (root / "crates", root / "apps" / "desktop" / "src-tauri" / "src")
    for scan_root in scan_roots:
        if scan_root.exists():
            for path in sorted(
                source
                for source in scan_root.rglob("*")
                if source.is_file() and source.suffix in {".rs", ".m", ".mm"}
            ):
                if adapter in path.parents:
                    continue
                if MACOS_XPC_NATIVE_MARKERS.search(path.read_text(encoding="utf-8")):
                    relative = path.relative_to(root).as_posix()
                    violations.append(f"{relative} uses native NSXPC symbols outside {MACOS_XPC_PACKAGE}")
    return violations
