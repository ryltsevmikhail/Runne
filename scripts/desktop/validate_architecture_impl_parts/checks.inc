#!/usr/bin/env python3
"""Dependency-boundary checks for the desktop architecture validator."""
import json
from pathlib import Path
import re
import subprocess
import sys


ALLOWED_RUST_DEPENDENCIES: dict[str, set[str]] = {
    "gocode-desktop": {"gocode-app-core", "gocode-platform-desktop"},
    "gocode-app-core": {
        "gocode-local-store",
        "gocode-platform-ports",
        "gocode-runtime-client",
        "gocode-secure-store",
    },
    "gocode-platform-desktop": {"gocode-api", "gocode-platform-ports", "gocode-runtime-client"},
    "gocode-platform-mobile": {"gocode-platform-ports"},
    "gocode-local-store": {"gocode-secure-store"},
    "gocode-platform-ports": set(),
    "gocode-pairing-crypto": set(),
    "gocode-runtime-client": {"gocode-api", "gocode-pairing-crypto"},
    "gocode-secure-store": {
        "gocode-api",
        "gocode-macos-keychain-acl",
        "gocode-provider",
    },
}
RENDERER_ROOT = Path("apps/desktop/src")
CONVERSATION_ENTITY_API = Path("apps/desktop/src/entities/conversation/api")
PROVIDER_TERMINAL_PERSISTENCE_ALLOWED = {
    Path("crates/gocode-runtime/src/provider_execution.rs"),
    Path("crates/gocode-runtime/src/provider_execution_parts/part_01.rs"),
    Path("crates/gocode-runtime/src/provider_execution_parts/part_05.rs"),
    Path("crates/gocode-store/src/provider/execution_store.rs"),
    Path("crates/gocode-store/src/provider/execution_store/decomposition/part_01.rs"),
    Path("crates/gocode-store/src/provider/execution_store/decomposition/part_06.rs"),
    Path("crates/gocode-store/src/provider/execution_store/decomposition/part_07.rs"),
    Path("crates/gocode-store/src/provider/execution_store/decomposition/part_08.rs"),
    Path("crates/gocode-store/src/provider/execution_store/decomposition/part_09.rs"),
    Path("crates/gocode-daemon/src/canonical_provider/runtime_store.rs"),
    Path("crates/gocode-daemon-loopback-fixture/src/ack_failure_store.rs"),
}
PROVIDER_TERMINAL_TEST_FEATURE = "provider-terminal-test-support"
RAW_PROVIDER_TERMINAL_TYPE = re.compile(r"\bProviderTerminalCommitRequest\b")
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
            if dependency.startswith("gocode-") and dependency not in allowed:
                violations.append(f"{package} -> {dependency} is forbidden")
    return violations


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
                dependency.get("name") == "gocode-runtime"
                and PROVIDER_TERMINAL_TEST_FEATURE in dependency.get("features", [])
                and dependency.get("kind") != "dev"
            ):
                violations.append(f"{package['name']} enables {PROVIDER_TERMINAL_TEST_FEATURE} outside dev-dependencies")
    return violations


def _is_forbidden_runtime_import(import_source: str) -> bool:
    normalized = import_source.lower().replace("_", "-")
    return "runtime-client" in normalized or "gocode-runtime" in normalized or any(
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
