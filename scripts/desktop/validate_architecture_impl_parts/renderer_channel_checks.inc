"""Renderer import, event, and typed-channel source checks."""
from __future__ import annotations


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
