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
        if "conversation" in lowered and any(
            _imports_generic_emit(match.group("imports"))
            for match in TAURI_EVENT_IMPORT_PATTERN.finditer(source)
        ):
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


def _imports_generic_emit(imports: str) -> bool:
    return any(
        imported.strip().split(" as ", maxsplit=1)[0].strip() in {"emit", "emitTo"}
        for imported in imports.split(",")
    )


def _constructs_typed_channel(source: str) -> bool:
    for match in TAURI_CORE_IMPORT_PATTERN.finditer(source):
        for imported in match.group("imports").split(","):
            parts = re.split(r"\s+as\s+", imported.strip())
            if parts[0] != "Channel":
                continue
            local_name = parts[-1]
            if re.search(rf"\bnew\s+{re.escape(local_name)}\s*\(", source):
                return True
    return False


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
