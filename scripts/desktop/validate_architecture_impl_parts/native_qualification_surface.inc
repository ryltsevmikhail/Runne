"""Closed public surface inspection for the pending qualification carrier."""
from __future__ import annotations

NATIVE_QUALIFICATION_PENDING = re.compile(
    r"(?s)(?P<attributes>(?:\s*#\[[^]]+\]\s*)*)pub\s+struct\s+"
    r"PendingQualificationFault\s*\{(?P<fields>[^}]*)\}"
)
NATIVE_QUALIFICATION_PENDING_IMPL = re.compile(
    r"(?m)^\s*impl(?:\s*<[^>{}]*>)?\s+"
    r"(?:(?:::)?(?:[A-Za-z_]\w*\s*::\s*)*)PendingQualificationFault"
    r"\s*(?:where\s+[^{}]+)?\s*\{"
)
NATIVE_QUALIFICATION_PENDING_METHOD = re.compile(
    r"(?P<visibility>\bpub(?:\s*\([^)]*\))?)\s+"
    r"(?P<modifiers>(?:(?:const|async|unsafe)\s+)*(?:extern\s+\"[^\"]*\"\s+)?)"
    r"fn\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<arguments>[^)]*)\)"
)
NATIVE_QUALIFICATION_PENDING_PUBLIC = re.compile(r"\bpub(?:\s*\([^)]*\))?")
NATIVE_QUALIFICATION_PENDING_TRAIT = re.compile(
    r"(?s)\bimpl(?:\s*<[^>{}]*>)?\s+[^{};]+?\s+for\s+"
    r"(?:::)?(?:[A-Za-z_]\w*\s*::\s*)*PendingQualificationFault\b"
)
NATIVE_QUALIFICATION_PENDING_METHODS = {
    "from_admitted_frame": "bytes:Vec<u8>",
    "verify_and_consume": "self,verifier:&mutcrate::QualificationFaultVerifier,context:&QualificationFaultContext,now_unix_seconds:u64",
    "encode_relay": "self,codec:&crate::QualificationFaultRelayCodecV1,binding:&runne_api::QualificationFaultRelayBindingV1",
}


def _mask_rust_comments_and_literals(text: str) -> str:
    """Blank non-code Rust text while preserving offsets and newlines."""
    masked = list(text)

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if masked[offset] != "\n":
                masked[offset] = " "

    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            end = index + 2
            depth = 1
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(index, end)
            index = end
            continue
        raw = re.match(r'(?:br|cr|r)(?P<hashes>#{0,255})"', text[index:])
        if raw and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")):
            terminator = '"' + raw.group("hashes")
            end = text.find(terminator, index + raw.end())
            end = len(text) if end < 0 else end + len(terminator)
            blank(index, end)
            index = end
            continue
        if text[index] == '"':
            end = index + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                    continue
                end += 1
                if text[end - 1] == '"':
                    break
            blank(index, min(end, len(text)))
            index = end
            continue
        character = re.match(r"'(?:\\.|[^'\\\n])'", text[index:])
        if character:
            end = index + character.end()
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(masked)


def _balanced_impl_bodies(text: str) -> list[str]:
    """Return brace-balanced inherent impl bodies for the exact carrier."""
    bodies = []
    for match in NATIVE_QUALIFICATION_PENDING_IMPL.finditer(text):
        depth = 1
        index = match.end()
        while index < len(text) and depth:
            depth += (text[index] == "{") - (text[index] == "}")
            index += 1
        if depth:
            return []
        bodies.append(text[match.end():index - 1])
    return bodies


def native_qualification_pending_surface_is_closed(text: str) -> bool:
    """Require the exact three-method consuming carrier surface and no traits."""
    text = _mask_rust_comments_and_literals(text)
    declarations = list(NATIVE_QUALIFICATION_PENDING.finditer(text))
    if not declarations:
        return True
    if len(declarations) != 1 or re.search(r"\bpub\b", declarations[0].group("fields")):
        return False
    attributes = declarations[0].group("attributes")
    if any(name in attributes for name in ("Clone", "Copy", "Debug", "Serialize", "Deserialize")):
        return False
    if NATIVE_QUALIFICATION_PENDING_TRAIT.search(text):
        return False
    methods = []
    for body in _balanced_impl_bodies(text):
        found = list(NATIVE_QUALIFICATION_PENDING_METHOD.finditer(body))
        if len(found) != len(NATIVE_QUALIFICATION_PENDING_PUBLIC.findall(body)):
            return False
        methods.extend(found)
    if len(methods) != len(NATIVE_QUALIFICATION_PENDING_METHODS):
        return False
    observed = {}
    for method in methods:
        name = method.group("name")
        arguments = re.sub(r"\s+", "", method.group("arguments")).rstrip(",")
        if method.group("visibility") != "pub" or method.group("modifiers") or name in observed:
            return False
        observed[name] = arguments
    return observed == NATIVE_QUALIFICATION_PENDING_METHODS
