"""Dependency-boundary checks for the desktop architecture validator."""
from __future__ import annotations
import json
from pathlib import Path
import re
import subprocess
import sys

ALLOWED_RUST_DEPENDENCIES: dict[str, set[str]] = {
    "runne-desktop": {
        "runne-api",
        "runne-app-core",
        "runne-macos-xpc",
        "runne-platform-desktop",
    },
    "runne-app-core": {
        "runne-local-store",
        "runne-api",
        "runne-platform-ports",
        "runne-runtime-client",
        "runne-secure-store",
    },
    "runne-platform-desktop": {
        "runne-api",
        "runne-macos-xpc",
        "runne-platform-ports",
        "runne-provider",
        "runne-runtime-client",
    },
    "runne-platform-mobile": {"runne-platform-ports"},
    "runne-local-store": {
        "runne-api",
        "runne-secure-store",
        "runne-sqlite-native-identity",
        "runne-windows-native-handle",
    },
    "runne-platform-ports": set(),
    "runne-pairing-crypto": set(),
    "runne-runtime-client": {"runne-api", "runne-pairing-crypto"},
    "runne-secure-store": {
        "runne-api",
        "runne-macos-keychain-acl",
        "runne-macos-xpc",
        "runne-provider",
    },
}
RENDERER_ROOT = Path("apps/desktop/src")
CONVERSATION_ENTITY_API = Path("apps/desktop/src/entities/conversation/api")
PROVIDER_TERMINAL_PERSISTENCE_ALLOWED = {
    Path("crates/runne-runtime/src/provider_execution.rs"),
    Path("crates/runne-runtime/src/provider_execution_parts/part_01.rs"),
    Path("crates/runne-runtime/src/provider_execution_parts/part_05.rs"),
    Path("crates/runne-store/src/provider/execution_store.rs"),
    Path("crates/runne-store/src/provider/execution_store/decomposition/part_01.rs"),
    Path("crates/runne-store/src/provider/execution_store/decomposition/part_06.rs"),
    Path("crates/runne-store/src/provider/execution_store/decomposition/part_07.rs"),
    Path("crates/runne-store/src/provider/execution_store/decomposition/part_08.rs"),
    Path("crates/runne-store/src/provider/execution_store/decomposition/part_09.rs"),
    Path("crates/runne-daemon/src/canonical_provider/runtime_store.rs"),
    Path("crates/runne-daemon-loopback-fixture/src/ack_failure_store.rs"),
    Path("crates/runne-daemon/src/protected_activation/loopback_fixture/ack_failure_store.rs"),
}
PROVIDER_TERMINAL_TEST_FEATURE = "provider-terminal-test-support"
RAW_PROVIDER_TERMINAL_TYPE = re.compile(r"\bProviderTerminalCommitRequest\b")
PROTECTED_ADMISSION_SOURCE = Path("crates/runne-api/src/protected_activation/root_admission.rs")
PROTECTED_ADMISSION_CONTROL_SOURCE = Path(
    "crates/runne-api/src/protected_activation/root_handle_control.rs"
)
PROTECTED_ADMISSION_SERVER_CARRIER_SOURCE = Path(
    "crates/runne-api/src/protected_activation/root_bind_transport.rs"
)
PROTECTED_ADMISSION_EXPOSURE = re.compile(
    r"pub\s+(?:const\s+)?fn\s+(?:admission_bytes|bytes|decode\w*|encode\w*|admission_string|as_str)\b"
)
PROTECTED_ADMISSION_FORBIDDEN_TRAIT = re.compile(
    r"\bimpl(?:<[^>{}]+>)?\s+(?:(?:[\w:]+::)?(?:Clone|Serialize|Deserialize|Deref(?:Mut)?|Borrow(?:Mut)?)|(?:[\w:]+::)?As(?:Ref|Mut))(?:<[^>{}]+>)?\s+for\s+ProtectedRootHandleAdmission\b"
)
PROTECTED_ADMISSION_BORROWED_TRANSITION = re.compile(
    r"pub\s+fn\s+into_root_bind_transport\s*\(\s*(?:&\s*(?:mut\s+)?self|self\s*:\s*&)",
)
ROOT_RESULT_ORDINARY_ADMISSION = re.compile(
    r"(?s)pub\s+fn\s+admitted\s*\([^)]*\bRootHandleAdmission\b"
)
ROOT_RESULT_PUBLIC_PROMOTION = re.compile(
    r"(?s)impl\s+RootHandleTransferResult\s*\{.*?pub\s+fn\s+into_admission\b"
)
SERVER_CARRIER_IMPLEMENTATION = re.compile(
    r"(?ms)^impl\s+RootBindAdmission\s*\{(?P<body>.*?)(?=^impl|^#\[|\Z)"
)
IMPORT_SOURCE_PATTERN = re.compile(r"""\b(?:from|import)\s*(?:\(\s*)?["']([^"']+)["']""")
TAURI_EVENT_IMPORT_PATTERN = re.compile(
    r"""import\s*\{(?P<imports>[^}]*)\}\s*from\s*["']@tauri-apps/api/event["']""", re.DOTALL
)
TAURI_CORE_IMPORT_PATTERN = re.compile(
    r"""import\s*\{(?P<imports>[^}]*)\}\s*from\s*["']@tauri-apps/api/core["']""", re.DOTALL
)
JAVASCRIPT_IDENTIFIER = r"[$A-Za-z_][$\w]*"


def find_rust_dependency_violations(dependencies: dict[str, set[str]]) -> list[str]:
    violations = []
    for package, package_dependencies in sorted(dependencies.items()):
        allowed = ALLOWED_RUST_DEPENDENCIES.get(package, set())
        for dependency in sorted(package_dependencies):
            if dependency.startswith("runne-") and dependency not in allowed:
                violations.append(f"{package} -> {dependency} is forbidden")
    return violations


def _tracked_dependency(package: str, dependency: dict) -> bool:
    if not dependency["name"].startswith("runne-"):
        return False
    if dependency["name"] == "runne-windows-native-handle" and package in {"runne-local-store", "runne-platform-desktop"}:
        return dependency.get("target") != "cfg(windows)"
    return True


def find_renderer_conversation_violations(root: Path) -> list[str]:
    violations = []
    renderer_root = root / RENDERER_ROOT
    if not renderer_root.exists():
        return violations
    sources = sorted(
        path for path in renderer_root.rglob("*") if path.is_file() and path.suffix in {".ts", ".tsx", ".vue"}
    )
    for path in sources:
        source = path.read_text(encoding="utf-8")
        relative_path = path.relative_to(root).as_posix()
        for import_source in IMPORT_SOURCE_PATTERN.findall(source):
            if _is_forbidden_runtime_import(import_source):
                violations.append(f"{relative_path} imports forbidden runtime/replay module {import_source}")
        if "conversation" in source.lower() and _emits_through_generic_tauri_events(source):
            violations.append(f"{relative_path} emits Conversation payloads through generic Tauri events")
        if not _is_conversation_entity_api(path, root) and _constructs_typed_channel(source):
            violations.append(f"{relative_path} constructs a Conversation channel outside entities/conversation/api")
    return violations


def find_provider_terminal_persistence_violations(root: Path) -> list[str]:
    """Keep the opaque accounting/outbox command inside runtime persistence."""
    violations = []
    roots = (root / "crates", root / "apps" / "desktop" / "src-tauri" / "src")
    sources = sorted(
        path for source_root in roots if source_root.exists() for path in source_root.rglob("*.rs")
        if "tests" not in path.relative_to(root).parts
    )
    for path in sources:
        relative = path.relative_to(root)
        if relative not in PROVIDER_TERMINAL_PERSISTENCE_ALLOWED and RAW_PROVIDER_TERMINAL_TYPE.search(path.read_text(encoding="utf-8")):
            violations.append(f"{relative.as_posix()} accesses raw provider terminal persistence outside the runtime-owned boundary")
    return violations


def find_provider_terminal_test_feature_violations(packages: list[dict]) -> list[str]:
    """Prevent test-only terminal forging on production dependency edges."""
    violations = []
    for package in packages:
        for dependency in package.get("dependencies", []):
            if (
                dependency.get("name") == "runne-runtime"
                and PROVIDER_TERMINAL_TEST_FEATURE in dependency.get("features", [])
                and dependency.get("kind") != "dev"
            ):
                violations.append(f"{package['name']} enables {PROVIDER_TERMINAL_TEST_FEATURE} outside dev-dependencies")
    return violations


def find_protected_admission_surface_violations(root: Path) -> list[str]:
    """Keep the verified root-admission wrapper move-only and byte-redacted."""
    source = root / PROTECTED_ADMISSION_SOURCE
    if not source.exists():
        return []
    text = source.read_text(encoding="utf-8")
    declaration = re.search(
        r"(?s)(?P<attributes>(?:\s*#\[[^]]+\]\s*)*)pub\s+struct\s+ProtectedRootHandleAdmission\b",
        text,
    )
    attributes = declaration.group("attributes") if declaration else ""
    implementations = re.findall(
        r"(?ms)^impl\s+ProtectedRootHandleAdmission\s*\{(?P<body>.*?)(?=^impl|\Z)",
        text,
    )
    derives_forbidden = "derive" in attributes and any(
        name in attributes for name in ("Clone", "Serialize", "Deserialize")
    )
    exposes_raw_surface = any(
        PROTECTED_ADMISSION_EXPOSURE.search(body)
        or PROTECTED_ADMISSION_BORROWED_TRANSITION.search(body)
        for body in implementations
    )
    violations = []
    if derives_forbidden or exposes_raw_surface or PROTECTED_ADMISSION_FORBIDDEN_TRAIT.search(text):
        violations.append(
            f"{PROTECTED_ADMISSION_SOURCE.as_posix()} exposes raw protected-admission surface"
        )
    control = root / PROTECTED_ADMISSION_CONTROL_SOURCE
    if control.exists():
        control_text = control.read_text(encoding="utf-8")
        if ROOT_RESULT_ORDINARY_ADMISSION.search(control_text):
            violations.append(
                f"{PROTECTED_ADMISSION_CONTROL_SOURCE.as_posix()} accepts ordinary admission into a protected result"
            )
        if ROOT_RESULT_PUBLIC_PROMOTION.search(control_text):
            violations.append(
                f"{PROTECTED_ADMISSION_CONTROL_SOURCE.as_posix()} promotes an unverified result into protected provenance"
            )
    carrier = root / PROTECTED_ADMISSION_SERVER_CARRIER_SOURCE
    if carrier.exists():
        carrier_text = carrier.read_text(encoding="utf-8")
        carrier_promotes = any(
            "ProtectedRootHandleAdmission" in match.group("body")
            or "into_protected" in match.group("body")
            for match in SERVER_CARRIER_IMPLEMENTATION.finditer(carrier_text)
        )
        if carrier_promotes:
            violations.append(
                f"{PROTECTED_ADMISSION_SERVER_CARRIER_SOURCE.as_posix()} promotes the untrusted server carrier"
            )
    return violations


def _is_forbidden_runtime_import(import_source: str) -> bool:
    normalized = import_source.lower().replace("_", "-")
    return "runtime-client" in normalized or "runne-runtime" in normalized or any(
        "replay" in segment for segment in normalized.split("/")
    )


def _emits_through_generic_tauri_events(source: str) -> bool:
    module = "@tauri-apps/api/event"
    if any(
        _named_static_binding(imported, {"emit", "emitTo"}) is not None
        for match in TAURI_EVENT_IMPORT_PATTERN.finditer(source)
        for imported in match.group("imports").split(",")
    ):
        return True
    if _dynamic_destructured_bindings(source, module, {"emit", "emitTo"}):
        return True
    aliases = _module_object_aliases(source, module)
    return _calls_object_member(source, aliases, {"emit", "emitTo"}) or bool(
        _direct_dynamic_member_pattern(module, {"emit", "emitTo"}).search(source)
    )


def _constructs_typed_channel(source: str) -> bool:
    for match in TAURI_CORE_IMPORT_PATTERN.finditer(source):
        for imported in match.group("imports").split(","):
            local_name = _named_static_binding(imported, {"Channel"})
            if local_name is not None and re.search(rf"\bnew\s+{re.escape(local_name)}\s*\(", source):
                return True
    module = "@tauri-apps/api/core"
    if any(re.search(rf"\bnew\s+{re.escape(name)}\s*\(", source) for name in _dynamic_destructured_bindings(source, module, {"Channel"})):
        return True
    aliases = _module_object_aliases(source, module)
    return _constructs_object_member(source, aliases, "Channel") or bool(
        _direct_dynamic_constructor_pattern(module, "Channel").search(source)
    )


def _named_static_binding(imported: str, exports: set[str]) -> str | None:
    parts = re.split(r"\s+as\s+", imported.strip())
    return parts[-1] if parts[0] in exports else None


def _dynamic_destructured_bindings(source: str, module: str, exports: set[str]) -> set[str]:
    pattern = re.compile(
        rf"""\b(?:const|let|var)\s*\{{(?P<imports>[^}}]*)\}}\s*=\s*
            (?:await\s+)?import\(\s*["']{re.escape(module)}["']\s*\)""", re.DOTALL | re.VERBOSE
    )
    bindings = set()
    for match in pattern.finditer(source):
        for imported in match.group("imports").split(","):
            parts = re.split(r"\s*:\s*", imported.strip())
            if parts[0] in exports:
                bindings.add(parts[-1])
    return bindings


def _module_object_aliases(source: str, module: str) -> set[str]:
    static_pattern = re.compile(
        rf"""\bimport\s+(?:\*\s+as\s+)?(?P<alias>{JAVASCRIPT_IDENTIFIER})
            (?:\s*,[^;]+)?\s+from\s*["']{re.escape(module)}["']""", re.DOTALL | re.VERBOSE
    )
    dynamic_pattern = re.compile(
        rf"""\b(?:const|let|var)\s+(?P<alias>{JAVASCRIPT_IDENTIFIER})\s*=\s*
            (?:await\s+)?import\(\s*["']{re.escape(module)}["']\s*\)""", re.DOTALL | re.VERBOSE
    )
    return {match.group("alias") for pattern in (static_pattern, dynamic_pattern) for match in pattern.finditer(source)}


def _calls_object_member(source: str, aliases: set[str], members: set[str]) -> bool:
    return any(re.search(rf"\b{_object_member_access(alias, member)}", source) for alias in aliases for member in members)


def _constructs_object_member(source: str, aliases: set[str], member: str) -> bool:
    return any(
        re.search(rf"\bnew\s+(?:{_object_member_access(alias, member)}|\(\s*{_object_member_access(alias, member)}\s*\))\s*\(", source)
        for alias in aliases
    )


def _object_member_access(alias: str, member: str) -> str:
    return rf"{re.escape(alias)}\s*(?:\?\.\s*(?:{re.escape(member)}|\[\s*[\"']{re.escape(member)}[\"']\s*\])|\.\s*{re.escape(member)}|\[\s*[\"']{re.escape(member)}[\"']\s*\])"


def _direct_dynamic_member_pattern(module: str, members: set[str]) -> re.Pattern:
    alternatives = "|".join(sorted(re.escape(member) for member in members))
    return re.compile(
        rf"""(?:\(\s*)?(?:await\s+)?import\(\s*["']{re.escape(module)}["']\s*\)
            (?:\s*\))?\s*(?:\?\.\s*(?:(?:{alternatives})|\[\s*["'](?:{alternatives})["']\s*\])|\.\s*(?:{alternatives})|\[\s*["'](?:{alternatives})["']\s*\])""",
        re.DOTALL | re.VERBOSE,
    )
