"""Closed dependency and source boundary for native qualification tickets."""
from __future__ import annotations

NATIVE_QUALIFICATION_PACKAGE = "runne-native-qualification"
NATIVE_QUALIFICATION_DEPENDENCIES = {
    "base64", "ed25519-dalek", "hex", "runne-api", "serde", "serde_json", "sha2",
}
ALLOWED_RUST_DEPENDENCIES[NATIVE_QUALIFICATION_PACKAGE] = {"runne-api"}
for owner in ("runne-desktop", "runne-platform-desktop"):
    ALLOWED_RUST_DEPENDENCIES[owner].add(NATIVE_QUALIFICATION_PACKAGE)
NATIVE_QUALIFICATION_EXACT_DEPENDENCIES = {
    ("normal", "base64"): ("=0.22.1", (), True),
    ("normal", "ed25519-dalek"): ("=2.1.1", (), True),
    ("normal", "hex"): ("^0.4", (), True),
    ("normal", "runne-api"): ("*", (), True),
    ("normal", "serde"): ("=1.0.229", ("derive",), True),
    ("normal", "serde_json"): ("=1.0.151", (), True),
    ("normal", "sha2"): ("=0.10.8", (), True),
    ("dev", "jsonschema"): ("=0.18.0", ("draft202012",), False),
    ("dev", "static_assertions"): ("=1.1.0", (), True),
    ("dev", "syn"): ("^2", ("extra-traits", "full", "visit"), True),
}
NATIVE_QUALIFICATION_FORBIDDEN_SOURCE = re.compile(
    r"\b(?:std::env|std::fs|std::path|SigningKey|File::|OpenOptions|dyn\s+Fn|impl\s+Fn)\b"
    r"|<\s*[A-Za-z_]\w*\s*:\s*Fn"
    r"|\bwhere\b[^;{]*\bFn(?:Once|Mut)?\s*\("
    r"|\buse\s+std\s*::\s*\{[^}]*\b(?:env|fs|path)\b"
)
NATIVE_QUALIFICATION_PROOF = re.compile(
    r"(?s)(?P<attributes>(?:\s*#\[[^]]+\]\s*)*)pub\s+struct\s+VerifiedQualificationFault\b"
)
NATIVE_QUALIFICATION_FORBIDDEN_PROOF_IMPL = re.compile(
    r"\bimpl(?:\s*<[^>{}]*>)?\s+"
    r"(?:"
    r"(?:(?:::)?(?:std|core)\s*::\s*clone\s*::\s*)?Clone"
    r"|(?:(?:::)?(?:std|core)\s*::\s*marker\s*::\s*)?Copy"
    r"|(?:(?:::)?serde\s*::\s*(?:ser\s*::\s*)?)?Serialize"
    r"|(?:(?:::)?serde\s*::\s*(?:de\s*::\s*)?)?Deserialize(?:\s*<[^>{}]*>)?"
    r")\s+for\s+(?:::)?(?:[A-Za-z_]\w*\s*::\s*)*VerifiedQualificationFault\b"
)
NATIVE_QUALIFICATION_ADMISSION_OWNERS = {
    "runne-desktop", "runne-platform-desktop", "runne-daemon",
}
NATIVE_QUALIFICATION_ADMISSION_TARGET = 'cfg(target_os = "macos")'
NATIVE_QUALIFICATION_ADMISSION_SOURCE = Path(
    "apps/desktop/src-tauri/src/qualification_ticket.rs"
)
NATIVE_QUALIFICATION_ADMISSION_ALLOWED = {
    NATIVE_QUALIFICATION_ADMISSION_SOURCE,
    Path("apps/desktop/src-tauri/src/qualification_ticket_tests.rs"),
    Path("apps/desktop/src-tauri/src/bundled_runtime.rs"),
    Path("apps/desktop/src-tauri/src/lib_parts/run.rs"),
    Path("apps/desktop/src-tauri/src/provider_credential_enrollment/dispatch.rs"),
    Path("apps/desktop/src-tauri/src/provider_credential_enrollment/prepared.rs"),
    Path("apps/desktop/src-tauri/src/provider_credential_enrollment/prepared/runner.rs"),
    Path("crates/runne-platform-desktop/src/protected_runtime.rs"),
    Path("crates/runne-platform-desktop/src/protected_runtime/qualification_relay.rs"),
    Path("crates/runne-platform-desktop/src/protected_runtime/qualification_relay_tests.rs"),
    Path("crates/runne-platform-desktop/src/updater_metadata/enrollment_tuple/measurement_facts.rs"),
    Path("crates/runne-daemon/src/protected_activation/control_v3.rs"),
    Path("crates/runne-daemon/src/protected_activation/control_v3/round.rs"),
    Path("crates/runne-daemon/src/protected_activation/control_v3/initial_exchange.rs"),
    Path("crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/tests.rs"),
    Path("crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/connected_tests.rs"),
}
NATIVE_QUALIFICATION_ADMISSION_TOKEN = re.compile(
    r"runne_native_qualification|PendingQualificationFault|QualificationFaultHostState|"
    r"QUALIFICATION_TICKET_DESCRIPTOR|admit_inherited_qualification_ticket|"
    r"\bqualification_ticket\b"
)
NATIVE_QUALIFICATION_ADMISSION_FORBIDDEN_OWNER = re.compile(
    r"#\s*\[\s*tauri::command\s*\]|std::env::(?:var|args|args_os)\s*\(|"
    r"std::fs::(?:read|read_to_string|write|copy|rename|remove\w*)\s*\(|"
    r"File::(?:open|create)\s*\(|profile\.sqlite3|rusqlite|"
    r"pub\s+fn\s+(?:bytes|as_bytes|serialize)\s*\(|"
    r"(?s:fn\s+(?:admit|admit_inherited_qualification_ticket)\b[^;{]*\bbool\b)"
)
NATIVE_QUALIFICATION_ADMISSION_FORBIDDEN_SETUP = re.compile(
    r"(?s:(?:qualification_ticket|qualification_faults|QualificationFaultHostState)"
    r"[^;{}]*(?:std::env|args_os|std::fs|File::|rusqlite|sqlite3)|"
    r"(?:std::env|args_os|std::fs|File::|rusqlite|sqlite3)[^;{}]*"
    r"(?:qualification_ticket|qualification_faults|QualificationFaultHostState))"
)
NATIVE_QUALIFICATION_DELIVERY_FORBIDDEN = re.compile(
    r"#\s*\[\s*tauri::command\s*\]|(?:^|[^\w])(?:::)?std::env::\w+\s*\(|"
    r"(?:^|[^\w])(?:::)?std::fs::\w+\s*\(|"
    r"(?:^|[^\w])(?:::)?std::fs::(?:File|OpenOptions)::\w+\s*\(|"
    r"(?:^|[^\w])(?:::)?std::path::(?:Path|PathBuf)::\w+\s*\(|"
    r"(?:File|OpenOptions)::(?:open|create|new)\s*\(|"
    r"rusqlite|sqlite3|reqwest|TcpStream|UdpSocket|"
    r"pub(?:\([^)]*\))?\s+(?:const\s+)?fn\s+(?:bytes|as_bytes|serialize|"
    r"(?:qualification|ticket)\w*(?:bytes|serialize)|"
    r"clone_\w*(?:qualification|ticket)|(?:qualification|ticket)\w*_clone)\s*\("
)


def find_native_qualification_dependency_violations(packages: list[dict]) -> list[str]:
    """Require one exact registry edge for every qualification dependency."""
    package = next(
        (row for row in packages if row.get("name") == NATIVE_QUALIFICATION_PACKAGE),
        None,
    )
    if package is None:
        return [f"{NATIVE_QUALIFICATION_PACKAGE} package is missing from workspace metadata"]
    violations = []
    api_packages = [row for row in packages if row.get("name") == "runne-api"]
    api_directory = None
    if len(api_packages) == 1:
        api_manifest = api_packages[0].get("manifest_path")
        if isinstance(api_manifest, str) and Path(api_manifest).name == "Cargo.toml":
            api_directory = Path(api_manifest).parent.resolve(strict=False)
    if api_directory is None:
        violations.append("runne-api package metadata is missing or ambiguous")
    manifest = package.get("manifest_path")
    if (
        not isinstance(manifest, str)
        or Path(manifest).name != "Cargo.toml"
        or Path(manifest).parent.name != NATIVE_QUALIFICATION_PACKAGE
    ):
        violations.append(f"{NATIVE_QUALIFICATION_PACKAGE} manifest_path is noncanonical")
    observed = set()
    for dependency in package.get("dependencies", []):
        name = dependency.get("name", "")
        kind = dependency.get("kind") or "normal"
        key = (kind, name)
        expected = NATIVE_QUALIFICATION_EXACT_DEPENDENCIES.get(key)
        shape = (
            dependency.get("req"),
            tuple(sorted(dependency.get("features", []))),
            dependency.get("uses_default_features", True),
        )
        path = dependency.get("path")
        source_is_exact = (
            dependency.get("source") is None
            and isinstance(path, str)
            and api_directory is not None
            and Path(path).resolve(strict=False) == api_directory
        ) if name == "runne-api" else (
            dependency.get("source") == CARGO_REGISTRY_SOURCE
            and path is None
        )
        exact_source = (
            source_is_exact
            and dependency.get("registry") is None
            and dependency.get("target") is None
            and dependency.get("rename") is None
            and dependency.get("optional", False) is False
        )
        if expected is None:
            violations.append(f"{NATIVE_QUALIFICATION_PACKAGE} -> {name} ({kind}) is forbidden")
        elif key in observed or shape != expected or not exact_source:
            violations.append(
                f"{NATIVE_QUALIFICATION_PACKAGE} -> {name} ({kind}) has forbidden shape"
            )
        observed.add(key)
    for kind, name in sorted(NATIVE_QUALIFICATION_EXACT_DEPENDENCIES.keys() - observed):
        violations.append(f"{NATIVE_QUALIFICATION_PACKAGE} -> {name} ({kind}) is missing")
    return sorted(violations)


def find_native_qualification_admission_dependency_violations(
    packages: list[dict],
) -> list[str]:
    """Allow only the three exact macOS native delivery owners."""
    observed = []
    for package in packages:
        for dependency in package.get("dependencies", []):
            if dependency.get("name") == NATIVE_QUALIFICATION_PACKAGE:
                observed.append((package.get("name", ""), dependency))
    violations = []
    owner_names = [owner for owner, _ in observed]
    if set(owner_names) != NATIVE_QUALIFICATION_ADMISSION_OWNERS or len(owner_names) != 3:
        violations.append("native qualification delivery must have exactly three owners")
    native_packages = [
        row for row in packages if row.get("name") == NATIVE_QUALIFICATION_PACKAGE
    ]
    native_directory = None
    if len(native_packages) == 1:
        manifest = native_packages[0].get("manifest_path")
        if isinstance(manifest, str) and Path(manifest).name == "Cargo.toml":
            native_directory = Path(manifest).parent.resolve(strict=False)
    if native_directory is None:
        violations.append("native qualification package metadata is missing or ambiguous")
    for owner, dependency in observed:
        path = dependency.get("path")
        canonical_path = (
            isinstance(path, str)
            and native_directory is not None
            and Path(path).resolve(strict=False) == native_directory
        )
        exact = (
            owner in NATIVE_QUALIFICATION_ADMISSION_OWNERS
            and (dependency.get("kind") or "normal") == "normal"
            and dependency.get("req") == "*"
            and dependency.get("target") == NATIVE_QUALIFICATION_ADMISSION_TARGET
            and dependency.get("source") is None
            and canonical_path
            and dependency.get("registry") is None
            and dependency.get("rename") is None
            and dependency.get("features", []) == []
            and dependency.get("uses_default_features", True) is True
            and dependency.get("optional", False) is False
        )
        if not exact:
            violations.append("native qualification admission dependency has forbidden shape")
    return sorted(violations)


def find_native_qualification_admission_surface_violations(root: Path) -> list[str]:
    """Keep pending fault-ticket authority inside one native Desktop module."""
    roots = (
        root / "apps/desktop/src",
        root / "apps/desktop/src-tauri/src",
        root / "crates/runne-cli/src",
        root / "crates/runne-runtime-client/src",
        root / "crates/runne-api/src",
        root / "crates/runne-platform-desktop/src",
        root / "crates/runne-daemon/src",
    )
    violations = []
    for source_root in roots:
        if not source_root.exists():
            continue
        for path in sorted(source_root.rglob("*")):
            if not path.is_file() or path.suffix not in {".rs", ".ts", ".tsx", ".vue"}:
                continue
            relative = path.relative_to(root)
            text = path.read_text(encoding="utf-8")
            if native_qualification_delivery_forbidden(relative, text):
                violations.append(
                    f"{relative.as_posix()} exposes forbidden qualification transport"
                )
            if (
                relative not in NATIVE_QUALIFICATION_ADMISSION_ALLOWED
                and NATIVE_QUALIFICATION_ADMISSION_TOKEN.search(text)
            ):
                violations.append(
                    f"{relative.as_posix()} exposes native qualification admission outside host"
                )
            if (
                relative == NATIVE_QUALIFICATION_ADMISSION_SOURCE
                and NATIVE_QUALIFICATION_ADMISSION_FORBIDDEN_OWNER.search(text)
            ):
                violations.append(
                    f"{relative.as_posix()} exposes forbidden qualification transport"
                )
            if (
                relative
                in {
                    Path("apps/desktop/src-tauri/src/bundled_runtime.rs"),
                    Path("apps/desktop/src-tauri/src/lib_parts/run.rs"),
                }
                and NATIVE_QUALIFICATION_ADMISSION_FORBIDDEN_SETUP.search(text)
            ):
                violations.append(
                    f"{relative.as_posix()} acquires qualification input through forbidden setup surface"
                )
    return violations


def find_native_qualification_violations(root: Path) -> list[str]:
    """Keep runtime key lookup, signing and cloneable proof surfaces out."""
    source_root = root / "crates" / NATIVE_QUALIFICATION_PACKAGE / "src"
    if not source_root.exists():
        return []
    violations = []
    for path in sorted(source_root.rglob("*.rs")):
        if "tests" in path.relative_to(source_root).parts:
            continue
        text = path.read_text(encoding="utf-8")
        if NATIVE_QUALIFICATION_FORBIDDEN_SOURCE.search(text):
            violations.append(f"{path.relative_to(root).as_posix()} has forbidden authority surface")
        match = NATIVE_QUALIFICATION_PROOF.search(text)
        derived_reusable = match and any(
            name in match.group("attributes")
            for name in ("Clone", "Copy", "Serialize", "Deserialize")
        )
        manually_reusable = NATIVE_QUALIFICATION_FORBIDDEN_PROOF_IMPL.search(text)
        if derived_reusable or manually_reusable:
            violations.append(f"{path.relative_to(root).as_posix()} makes verified fault reusable")
    return violations
