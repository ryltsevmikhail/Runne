"""Exclusive Data Protection Keychain boundary for provider credentials."""
from __future__ import annotations

CREDENTIAL_SERVICE_PACKAGE = "runne-credential-service"
CREDENTIAL_KEYCHAIN_SYMBOLS = re.compile(
    r"\bSecItem(?:Add|Update|Delete|CopyMatching)\b"
)
CREDENTIAL_KEYCHAIN_REQUIRED_MARKERS = (
    "SecItemAdd",
    "SecItemCopyMatching",
    "SecItemDelete",
    "kSecClassGenericPassword",
    "kSecAttrService",
    "kSecAttrAccount",
    "kSecAttrAccessGroup",
    "kSecAttrSynchronizable",
    "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    "kSecUseDataProtectionKeychain",
    "758F9Z45SR.com.runne.credential-service",
)
CREDENTIAL_KEYCHAIN_LEGACY_ACL = re.compile(
    r"\b(?:SecAccess[A-Za-z0-9_]*|kSecAttrAccess)\b"
)
CREDENTIAL_SERVICE_NATIVE_TARGET = 'cfg(target_os = "macos")'
CREDENTIAL_SERVICE_DEPENDENCIES = {
    "hex": None,
    "runne-credential-service-core": None,
    "runne-macos-xpc": None,
    "runne-provider": None,
    "zeroize": None,
    "core-foundation": CREDENTIAL_SERVICE_NATIVE_TARGET,
    "core-foundation-sys": CREDENTIAL_SERVICE_NATIVE_TARGET,
    "security-framework-sys": CREDENTIAL_SERVICE_NATIVE_TARGET,
}


def find_credential_service_dependency_violations(
    packages: list[dict], root: Path
) -> list[str]:
    """Require the minimal service dependency set and sole core composition."""
    matches = [package for package in packages if package.get("name") == CREDENTIAL_SERVICE_PACKAGE]
    if len(matches) != 1:
        return [f"{CREDENTIAL_SERVICE_PACKAGE} package is missing or duplicated"]
    package = matches[0]
    expected_manifest = root.resolve() / "crates" / CREDENTIAL_SERVICE_PACKAGE / "Cargo.toml"
    manifest = package.get("manifest_path")
    violations = []
    if not isinstance(manifest, str) or Path(manifest).resolve() != expected_manifest:
        violations.append(f"{CREDENTIAL_SERVICE_PACKAGE} manifest_path is noncanonical")
    observed = set()
    for dependency in package.get("dependencies", []):
        name = dependency.get("name", "<unnamed>")
        if name in observed or name not in CREDENTIAL_SERVICE_DEPENDENCIES:
            violations.append(f"{CREDENTIAL_SERVICE_PACKAGE} -> {name} is outside exact allowlist")
        elif dependency.get("target") != CREDENTIAL_SERVICE_DEPENDENCIES[name]:
            violations.append(f"{CREDENTIAL_SERVICE_PACKAGE} -> {name} has forbidden target scope")
        observed.add(name)
    for name in sorted(CREDENTIAL_SERVICE_DEPENDENCIES.keys() - observed):
        violations.append(f"{CREDENTIAL_SERVICE_PACKAGE} -> {name} dependency is missing")
    for candidate in packages:
        if candidate.get("name") == CREDENTIAL_SERVICE_PACKAGE:
            continue
        if any(
            dependency.get("name") == "runne-credential-service-core"
            for dependency in candidate.get("dependencies", [])
        ):
            violations.append(
                f"{candidate.get('name', '<unnamed>')} composes credential service core outside service"
            )
    return violations


def find_credential_keychain_boundary_violations(root: Path) -> list[str]:
    """Keep credential item APIs and exact DPK policy inside one service."""
    service = root / "crates" / CREDENTIAL_SERVICE_PACKAGE
    sources = service / "src"
    if not sources.exists():
        return [f"crates/{CREDENTIAL_SERVICE_PACKAGE} source boundary is missing"]
    service_files = sorted(
        path for path in sources.rglob("*")
        if path.is_file() and path.suffix in {".rs", ".m", ".mm"}
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in service_files)
    violations = []
    for marker in CREDENTIAL_KEYCHAIN_REQUIRED_MARKERS:
        if marker not in combined:
            violations.append(f"{CREDENTIAL_SERVICE_PACKAGE} misses exact Keychain marker {marker}")
    if CREDENTIAL_KEYCHAIN_LEGACY_ACL.search(combined):
        violations.append(f"{CREDENTIAL_SERVICE_PACKAGE} uses forbidden legacy SecAccess ACL")
    for path in service_files:
        if len(path.read_text(encoding="utf-8").splitlines()) > 300:
            relative = path.relative_to(root).as_posix()
            violations.append(f"{relative} exceeds the 300-line credential service limit")
    scan_roots = (root / "crates", root / "apps" / "desktop" / "src-tauri" / "src")
    for scan_root in scan_roots:
        if not scan_root.exists():
            continue
        for path in sorted(
            candidate for candidate in scan_root.rglob("*")
            if candidate.is_file() and candidate.suffix in {".rs", ".m", ".mm"}
        ):
            if service in path.parents:
                continue
            if CREDENTIAL_KEYCHAIN_SYMBOLS.search(path.read_text(encoding="utf-8")):
                relative = path.relative_to(root).as_posix()
                violations.append(
                    f"{relative} uses credential Keychain symbols outside {CREDENTIAL_SERVICE_PACKAGE}"
                )
    return violations
