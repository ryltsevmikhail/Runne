#!/usr/bin/env python3
"""Validate repository dependency boundaries."""

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
    "gocode-platform-desktop": {"gocode-platform-ports"},
    "gocode-platform-mobile": {"gocode-platform-ports"},
    "gocode-local-store": {"gocode-secure-store"},
    "gocode-platform-ports": set(),
    "gocode-pairing-crypto": set(),
    "gocode-runtime-client": set(),
    "gocode-secure-store": set(),
}

RENDERER_ROOT = Path("apps/desktop/src")
CONVERSATION_ENTITY_API = Path("apps/desktop/src/entities/conversation/api")
IMPORT_SOURCE_PATTERN = re.compile(
    r"""\b(?:from|import)\s*(?:\(\s*)?["']([^"']+)["']"""
)
TAURI_EVENT_IMPORT_PATTERN = re.compile(
    r"""import\s*\{(?P<imports>[^}]*)\}\s*from\s*["']@tauri-apps/api/event["']""",
    re.DOTALL,
)
TAURI_CORE_IMPORT_PATTERN = re.compile(
    r"""import\s*\{(?P<imports>[^}]*)\}\s*from\s*["']@tauri-apps/api/core["']""",
    re.DOTALL,
)
JAVASCRIPT_IDENTIFIER = r"[$A-Za-z_][$\w]*"


def find_rust_dependency_violations(
    dependencies: dict[str, set[str]],
) -> list[str]:
    violations: list[str] = []
    for package, package_dependencies in sorted(dependencies.items()):
        allowed = ALLOWED_RUST_DEPENDENCIES.get(package, set())
        for dependency in sorted(package_dependencies):
            if dependency.startswith("gocode-") and dependency not in allowed:
                violations.append(f"{package} -> {dependency} is forbidden")
    return violations


def find_renderer_conversation_violations(root: Path) -> list[str]:
    violations: list[str] = []
    renderer_root = root / RENDERER_ROOT
    if not renderer_root.exists():
        return violations

    sources = sorted(
        path
        for path in renderer_root.rglob("*")
        if path.is_file() and path.suffix in {".ts", ".tsx", ".vue"}
    )
    for path in sources:
        source = path.read_text(encoding="utf-8")
        relative_path = path.relative_to(root).as_posix()
        for import_source in IMPORT_SOURCE_PATTERN.findall(source):
            if _is_forbidden_runtime_import(import_source):
                violations.append(
                    f"{relative_path} imports forbidden runtime/replay module "
                    f"{import_source}"
                )

        lowered = source.lower()
        if "conversation" in lowered and _emits_through_generic_tauri_events(source):
            violations.append(
                f"{relative_path} emits Conversation payloads through generic "
                "Tauri events"
            )

        if not _is_conversation_entity_api(path, root) and _constructs_typed_channel(
            source
        ):
            violations.append(
                f"{relative_path} constructs a Conversation channel outside "
                "entities/conversation/api"
            )
    return violations


def _is_forbidden_runtime_import(import_source: str) -> bool:
    normalized = import_source.lower().replace("_", "-")
    segments = normalized.split("/")
    return (
        "runtime-client" in normalized
        or "gocode-runtime" in normalized
        or any("replay" in segment for segment in segments)
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
            if local_name is not None and re.search(
                rf"\bnew\s+{re.escape(local_name)}\s*\(", source
            ):
                return True
    module = "@tauri-apps/api/core"
    for local_name in _dynamic_destructured_bindings(source, module, {"Channel"}):
        if re.search(rf"\bnew\s+{re.escape(local_name)}\s*\(", source):
            return True
    aliases = _module_object_aliases(source, module)
    return _constructs_object_member(source, aliases, "Channel") or bool(
        _direct_dynamic_constructor_pattern(module, "Channel").search(source)
    )


def _named_static_binding(imported: str, exports: set[str]) -> str | None:
    parts = re.split(r"\s+as\s+", imported.strip())
    if parts[0] not in exports:
        return None
    return parts[-1]


def _dynamic_destructured_bindings(
    source: str, module: str, exports: set[str]
) -> set[str]:
    pattern = re.compile(
        rf"""\b(?:const|let|var)\s*\{{(?P<imports>[^}}]*)\}}\s*=\s*
            (?:await\s+)?import\(\s*["']{re.escape(module)}["']\s*\)""",
        re.DOTALL | re.VERBOSE,
    )
    bindings: set[str] = set()
    for match in pattern.finditer(source):
        for imported in match.group("imports").split(","):
            parts = re.split(r"\s*:\s*", imported.strip())
            if parts[0] in exports:
                bindings.add(parts[-1])
    return bindings


def _module_object_aliases(source: str, module: str) -> set[str]:
    static_pattern = re.compile(
        rf"""\bimport\s+(?:\*\s+as\s+)?(?P<alias>{JAVASCRIPT_IDENTIFIER})
            (?:\s*,[^;]+)?\s+from\s*["']{re.escape(module)}["']""",
        re.DOTALL | re.VERBOSE,
    )
    dynamic_pattern = re.compile(
        rf"""\b(?:const|let|var)\s+(?P<alias>{JAVASCRIPT_IDENTIFIER})\s*=\s*
            (?:await\s+)?import\(\s*["']{re.escape(module)}["']\s*\)""",
        re.DOTALL | re.VERBOSE,
    )
    return {
        match.group("alias")
        for pattern in (static_pattern, dynamic_pattern)
        for match in pattern.finditer(source)
    }


def _calls_object_member(
    source: str, aliases: set[str], members: set[str]
) -> bool:
    for alias in aliases:
        for member in members:
            access = _object_member_access(alias, member)
            if re.search(rf"\b{access}", source):
                return True
    return False


def _constructs_object_member(source: str, aliases: set[str], member: str) -> bool:
    for alias in aliases:
        access = _object_member_access(alias, member)
        if re.search(
            rf"\bnew\s+(?:{access}|\(\s*{access}\s*\))\s*\(", source
        ):
            return True
    return False


def _object_member_access(alias: str, member: str) -> str:
    return (
        rf"{re.escape(alias)}\s*(?:"
        rf"\?\.\s*(?:{re.escape(member)}|"
        rf"\[\s*[\"']{re.escape(member)}[\"']\s*\])|"
        rf"\.\s*{re.escape(member)}|"
        rf"\[\s*[\"']{re.escape(member)}[\"']\s*\])"
    )


def _direct_dynamic_member_pattern(module: str, members: set[str]) -> re.Pattern:
    alternatives = "|".join(sorted(re.escape(member) for member in members))
    return re.compile(
        rf"""(?:\(\s*)?(?:await\s+)?import\(\s*["']{re.escape(module)}["']\s*\)
            (?:\s*\))?\s*(?:\?\.\s*(?:(?:{alternatives})|
            \[\s*["'](?:{alternatives})["']\s*\])|
            \.\s*(?:{alternatives})|
            \[\s*["'](?:{alternatives})["']\s*\])""",
        re.DOTALL | re.VERBOSE,
    )


def _direct_dynamic_constructor_pattern(module: str, member: str) -> re.Pattern:
    return re.compile(
        rf"""\bnew\s+(?:\(\s*)?(?:\(\s*)?(?:await\s+)?import\(
            \s*["']{re.escape(module)}["']\s*\)(?:\s*\))?\s*(?:
            \?\.\s*(?:{re.escape(member)}|
            \[\s*["']{re.escape(member)}["']\s*\])|
            \.\s*{re.escape(member)}|
            \[\s*["']{re.escape(member)}["']\s*\])(?:\s*\))?\s*\(""",
        re.DOTALL | re.VERBOSE,
    )


def _is_conversation_entity_api(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root / CONVERSATION_ENTITY_API)
        return True
    except ValueError:
        return False


def load_workspace_dependencies(root: Path) -> dict[str, set[str]]:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    return {
        package["name"]: {
            dependency["name"]
            for dependency in package["dependencies"]
            if dependency["name"].startswith("gocode-")
        }
        for package in metadata["packages"]
        if package["name"] in ALLOWED_RUST_DEPENDENCIES
    }


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    violations = find_rust_dependency_violations(
        load_workspace_dependencies(root)
    ) + find_renderer_conversation_violations(root)
    if violations:
        for violation in violations:
            print(f"ERROR: {violation}")
        return 1
    print("Rust and renderer dependency boundaries passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
