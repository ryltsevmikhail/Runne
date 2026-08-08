"""Fail-closed parser for the deliberately small documentation YAML subset."""
import re


KEYS = {"title", "status", "document_type", "source_status", "created", "updated", "owners"}
KEY_RE = re.compile(r"^[a-z_]+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
COERCIBLE_RE = re.compile(r"^(?:yes|no|true|false|null|~|[-+]?\d+(?:\.\d+)?)$", re.I)


def fail(code):
    raise ValueError(code)


def parse_restricted_front_matter(raw: bytes) -> dict[str, str]:
    """Parse one closed, scalar-only front-matter document from UTF-8 bytes."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("FM_INVALID_UTF8")
    lines = text.splitlines()
    if lines and lines[0] == "---":
        try:
            end = lines.index("---", 1)
        except ValueError:
            fail("FM_UNTERMINATED")
        if any(line == "---" for line in lines[end + 1:]):
            fail("FM_UNSUPPORTED_YAML")
        lines = lines[1:end]
    elif any(line == "---" for line in lines):
        fail("FM_UNSUPPORTED_YAML")
    result = {}
    declared = set()
    for line in lines:
        if line and not line.startswith(("#", "- ", " ", "\t")) and ":" in line:
            key = line.split(":", 1)[0]
            if KEY_RE.fullmatch(key):
                if key in declared:
                    fail("FM_DUPLICATE_KEY")
                declared.add(key)
    active_list = None
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if any(marker in line for marker in ("&", "*", "!", "{", "}", "[", "]")):
            fail("FM_UNSUPPORTED_YAML")
        if line.startswith("- "):
            if active_list is None:
                fail("FM_INVALID_LIST")
            value = line[2:]
            if not value or value.startswith(("\"", "'")) or ":" in value:
                fail("FM_INVALID_LIST")
            result[active_list] = ",".join(filter(None, (result[active_list], value)))
            continue
        if ":" not in line or line.startswith((" ", "\t")):
            fail("FM_INVALID_LINE")
        key, value = line.split(":", 1)
        if not KEY_RE.fullmatch(key):
            fail("FM_INVALID_KEY")
        if key not in KEYS:
            fail("FM_UNKNOWN_KEY")
        value = value.strip()
        active_list = None
        if not value:
            if key != "owners":
                fail("FM_EMPTY_VALUE")
            result[key] = ""
            active_list = key
        elif (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            if len(value) < 2:
                fail("FM_INVALID_STRING")
            result[key] = value[1:-1]
        elif DATE_RE.fullmatch(value):
            result[key] = value
        elif COERCIBLE_RE.fullmatch(value):
            fail("FM_IMPLICIT_SCALAR")
        else:
            fail("FM_UNQUOTED_STRING")
    return result
