"""Fail-closed protected-vocabulary scanner for the staged Markdown delta."""
import re
import unicodedata
from html import unescape


_STATUS = ("accepted", "approved", "final", "complete", "verified", "authorized", "pass", "satisfied")
_IGNORABLE = {"\u00ad", "\u034f", "\u061c", "\u115f", "\u1160", "\u17b4", "\u17b5", "\u180e", "\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2060", "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff", *map(chr, range(0xfe00, 0xfe10))}
_SKELETON = str.maketrans("аесорхіјѕгον", "aecoxpijsrov")


def _projection(text: str) -> str:
    text = unescape(text)
    text = re.sub(r"<!--[\s\S]*?-->", "", text)
    text = re.sub(r"```[\s\S]*?```|`[^`]*`", "", text)
    text = re.sub(r"\[([^]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[*_]+", "", text)
    return unicodedata.normalize("NFKC", text).casefold()


def _mixed_script_claim_token(text: str) -> bool:
    patterns = (r"\b(?:status|decision|disposition)\s*[:=-]\s*(\S+)", r"\bauthority\s*(?:[:=-]\s*|-\s*|is\s+)(?!not\b)(\S+)", r"\b(?:is|are|was|were|has been|have been)\s+(?!not\b)(\S+?)[.!?]?(?=$|\n)", r"^\s*(\S+)\s*$")
    return any(any(char.isascii() and char.isalpha() for char in match.group(1)) and any(char.isalpha() and not char.isascii() for char in match.group(1)) for pattern in patterns for match in re.finditer(pattern, text, re.MULTILINE))


def protected_claim_diagnostics(value: str | bytes) -> list[str]:
    try:
        text = value.decode("utf-8") if isinstance(value, bytes) else value
    except UnicodeDecodeError:
        return ["DOCS_PROTECTED_UNICODE"]
    if not isinstance(text, str):
        return ["DOCS_PROTECTED_UNICODE"]
    if any(char in _IGNORABLE or unicodedata.category(char) == "Cf" for char in text):
        return ["DOCS_PROTECTED_UNICODE"]
    projected = _projection(text)
    if _mixed_script_claim_token(projected):
        return ["DOCS_PROTECTED_CONFUSABLE"]
    projected = projected.translate(_SKELETON)
    status = "(?:" + "|".join(_STATUS) + ")"
    for line in projected.splitlines():
        compact = re.sub(r"[^a-z0-9]+", "", line)
        if compact in _STATUS or re.search(rf"\b(?:status|decision|disposition)\s*[:=-]\s*{status}\b", line):
            return ["DOCS_AUTHORIZING_CLAIM"]
    for sentence in re.split(r"[.!?](?:\s|$)", projected):
        status_match = re.search(rf"\b(?:is|are|was|were|has been|have been)\s+{status}$", sentence.strip())
        if status_match and not re.search(r"\b(?:not|no|never|without|reject(?:s|ed|ing)?|deny|blocked|only when|unless|until)\b", sentence[:status_match.start()]):
            return ["DOCS_AUTHORIZING_CLAIM"]
        match = re.search(r"\bauthority\s*(?:[:=-]\s*|[- ]|is\s+)(?!not\b)granted\b|\bactive\s+activation\b", sentence)
        if match and not re.search(r"\b(?:not|no|never|without|reject(?:s|ed|ing)?|deny|blocked|only when|unless|until)\b", sentence[:match.start()]):
            return ["DOCS_AUTHORIZING_CLAIM"]
    return []
