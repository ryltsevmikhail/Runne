"""Lexical, fail-closed scan for native types escaping the XPC adapter."""
from __future__ import annotations

MACOS_XPC_FOUNDATION_TYPE = re.compile(
    r"\b(?:NSData|NSError|NSString|NSXPC\w*|SMAppService\w*)\b"
)
MACOS_XPC_PUBLIC_ITEM = re.compile(
    r"(?m)\bpub\s+(?:(?:async|const|unsafe)\s+)*"
    r'(?:extern(?:\s+"[^"]*")?\s+)?'
    r"(?P<kind>fn|struct|enum|union|trait|type|const|static)\b"
)
MACOS_XPC_PUBLIC_FOUNDATION_REEXPORT = re.compile(
    r"(?m)^\s*pub\s+use\s+[^;]*(?:\bNSData\b|\bNSError\b|\bNSString\b|\bNSXPC\w*\b|\bSMAppService\w*\b)"
)
MACOS_XPC_PUBLIC_FOUNDATION_FIELD = re.compile(
    r"(?m)^\s*pub\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*[^,\n]*"
    r"(?:\bNSData\b|\bNSError\b|\bNSString\b|\bNSXPC\w*\b|\bSMAppService\w*\b)"
)
MACOS_XPC_FOUNDATION_USE_ALIAS = re.compile(
    r"(?ms)\buse\b[^;]*(?:\bNSData\b|\bNSError\b|\bNSString\b|\bNSXPC\w*\b|\bSMAppService\w*\b)"
    r"[^;]*\bas\s+(?P<alias>(?:r#)?[A-Za-z_][A-Za-z0-9_]*)[^;]*;"
)
MACOS_XPC_FOUNDATION_TYPE_ALIAS = re.compile(
    r"(?ms)\btype\s+(?P<alias>(?:r#)?[A-Za-z_][A-Za-z0-9_]*)[^;=]*=\s*[^;]*"
    r"(?:\bNSData\b|\bNSError\b|\bNSString\b|\bNSXPC\w*\b|\bSMAppService\w*\b)[^;]*;"
)
MACOS_XPC_EXPORTED_MACRO = re.compile(
    r"(?ms)#\s*\[\s*macro_export\b[^]]*\]|\bpub\s+macro\b"
)


def _mask_rust_comments_and_strings(source: str) -> str:
    masked = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int, keep: set[str] | None = None) -> None:
        preserved = keep or set()
        for offset in range(start, end):
            if source[offset] != "\n" and source[offset] not in preserved:
                masked[offset] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end == -1 else end
            blank(index, end)
            index = end
        elif source.startswith("/*", index):
            depth, end = 1, index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth, end = depth + 1, end + 2
                elif source.startswith("*/", end):
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
            blank(index, end)
            index = end
        else:
            raw = re.match(r'(?:br|r)(?P<hashes>#{0,255})"', source[index:])
            quote = index + 1 if source.startswith('b"', index) else index
            if raw:
                marker = '"' + raw.group("hashes")
                close = source.find(marker, index + raw.end())
                end = length if close == -1 else close + len(marker)
                blank(index, end, {'"', '#'})
                index = end
            elif quote < length and source[quote] == '"':
                end = quote + 1
                while end < length:
                    if source[end] == "\\":
                        end += 2
                    elif source[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
                blank(index, min(end, length), {'"'})
                index = end
            else:
                index += 1
    return "".join(masked)


def _rust_item_header_end(source: str, start: int) -> tuple[int, str | None]:
    parentheses = brackets = 0
    for index in range(start, len(source)):
        character = source[index]
        parentheses += (character == "(") - (character == ")")
        brackets += (character == "[") - (character == "]")
        if character in "{;" and parentheses == 0 and brackets == 0:
            return index, character
    return len(source), None


def _matching_rust_delimiter(source: str, opening: int) -> int:
    pairs = {"{": "}", "(": ")", "[": "]"}
    opener = source[opening]
    closer = pairs[opener]
    depth = 0
    for index in range(opening, len(source)):
        depth += (source[index] == opener) - (source[index] == closer)
        if depth == 0:
            return index
    return len(source)


def _public_generating_macros(source: str) -> set[str]:
    generators = set()
    definitions = re.finditer(r"\bmacro_rules!\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{", source)
    for definition in definitions:
        opening = definition.end() - 1
        body = source[opening + 1 : _matching_rust_delimiter(source, opening)]
        if re.search(r"\bpub\s+", body):
            generators.add(definition.group(1))
    return generators


def rust_public_generating_macros(source: str) -> set[str]:
    return _public_generating_macros(_mask_rust_comments_and_strings(source))


def _public_macro_expands_foundation(source: str, public_generators) -> bool:
    if MACOS_XPC_EXPORTED_MACRO.search(source):
        return True
    for name in public_generators:
        invocations = re.finditer(rf"\b{re.escape(name)}!\s*([({{\[])", source)
        for invocation in invocations:
            opening = invocation.end() - 1
            close = _matching_rust_delimiter(source, opening)
            if MACOS_XPC_FOUNDATION_TYPE.search(source[opening + 1 : close]):
                return True
    return False


def rust_public_api_exposes_foundation(source: str, crate_generators=()) -> bool:
    masked = _mask_rust_comments_and_strings(source)
    aliases = {
        match.group("alias")
        for pattern in (
            MACOS_XPC_FOUNDATION_USE_ALIAS,
            MACOS_XPC_FOUNDATION_TYPE_ALIAS,
        )
        for match in pattern.finditer(masked)
    }

    def exposes(text: str) -> bool:
        return MACOS_XPC_FOUNDATION_TYPE.search(text) is not None or any(
            re.search(rf"\b{re.escape(alias)}\b", text) for alias in aliases
        )

    for item in MACOS_XPC_PUBLIC_ITEM.finditer(masked):
        end, delimiter = _rust_item_header_end(masked, item.end())
        if exposes(masked[item.start() : end + 1]):
            return True
        if delimiter == "{" and item.group("kind") in {"trait", "enum"}:
            close = _matching_rust_delimiter(masked, end)
            if exposes(masked[end + 1 : close]):
                return True
    public_fields = re.finditer(
        r"(?m)^\s*pub\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*[^,\n]*", masked
    )
    if any(exposes(match.group(0)) for match in public_fields):
        return True
    generators = set(crate_generators) | _public_generating_macros(masked)
    return _public_macro_expands_foundation(masked, generators) or any(
        pattern.search(masked)
        for pattern in (
            MACOS_XPC_PUBLIC_FOUNDATION_REEXPORT,
            MACOS_XPC_PUBLIC_FOUNDATION_FIELD,
        )
    )
