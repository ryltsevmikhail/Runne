import json
from dataclasses import dataclass

from scripts.release_v2.model import FailureCodeV1, ReleaseFailure


@dataclass(frozen=True)
class _Line:
    indent: int
    text: str


def parse_pnpm_lock(raw: str) -> dict[str, object]:
    """Grammar: two-space block maps/lists, quoted scalars and flat flow maps only."""
    if not raw or "\t" in raw:
        _fail()
    lines = tuple(_line(value) for value in raw.splitlines() if value)
    if not lines or lines[0].indent:
        _fail()
    value, index = _map(lines, 0, 0)
    if index != len(lines):
        _fail()
    return value


def _line(value: str) -> _Line:
    indent = len(value) - len(value.lstrip(" "))
    text = value[indent:]
    if not text or indent % 2 or text.startswith("#") or " #" in text or text.startswith(("&", "*", "!", "|", ">")) or ": &" in text or ": *" in text or ": !" in text:
        _fail()
    return _Line(indent, text)


def _map(lines: tuple[_Line, ...], index: int, indent: int) -> tuple[dict[str, object], int]:
    result: dict[str, object] = {}
    while index < len(lines) and lines[index].indent == indent:
        line = lines[index]
        key, scalar = _pair(line.text)
        if key in result:
            _fail()
        index += 1
        if scalar == "":
            if index >= len(lines) or lines[index].indent != indent + 2:
                _fail()
            if lines[index].text.startswith("- "):
                result[key], index = _list(lines, index, indent + 2)
            else:
                result[key], index = _map(lines, index, indent + 2)
        else:
            result[key] = _scalar(scalar)
        if index < len(lines) and lines[index].indent > indent:
            _fail()
    return result, index


def _list(lines: tuple[_Line, ...], index: int, indent: int) -> tuple[tuple[str, ...], int]:
    result = []
    while index < len(lines) and lines[index].indent == indent:
        text = lines[index].text
        if not text.startswith("- "):
            _fail()
        result.append(_scalar(text[2:]))
        index += 1
    return tuple(result), index


def _pair(value: str) -> tuple[str, str]:
    quote = ""
    depth = 0
    for index, character in enumerate(value):
        if quote:
            if character == quote:
                quote = ""
        elif character in "'\"":
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
            if depth < 0:
                _fail()
        elif character == ":" and not depth:
            key = _quoted(value[:index])
            remainder = value[index + 1:]
            if not key or (remainder and not remainder.startswith(" ")):
                _fail()
            return key, remainder[1:] if remainder else ""
    _fail()


def _scalar(value: str) -> object:
    if not value or value.startswith(("|", ">")):
        _fail()
    if value.startswith(("'", '"')):
        return _quoted(value)
    if _marked(value):
        _fail()
    if value == "{}":
        return {}
    if value.startswith("["):
        if not value.endswith("]"):
            _fail()
        for item in _split(value[1:-1], ","):
            if item.strip().startswith(("{", "[")):
                _fail()
        return value
    if value.startswith("{"):
        if not value.endswith("}"):
            _fail()
        return _flow_map(value[1:-1])
    return _quoted(value)


def _flow_map(value: str) -> dict[str, object]:
    if not value:
        return {}
    result: dict[str, object] = {}
    for pair in _split(value, ","):
        key, scalar = _pair(pair.strip())
        if key in result:
            _fail()
        if scalar.startswith(("{", "[")):
            _fail()
        result[key] = _scalar(scalar)
    return result


def _split(value: str, separator: str) -> tuple[str, ...]:
    quote, depth, start, result = "", 0, 0, []
    for index, character in enumerate(value):
        if quote:
            if character == quote:
                quote = ""
        elif character in "'\"":
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        elif character == separator and not depth:
            result.append(value[start:index])
            start = index + 1
    if quote or depth:
        _fail()
    result.append(value[start:])
    return tuple(result)


def _quoted(value: str) -> str:
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            _fail()
        return value[1:-1].replace("''", "'")
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as error:
            raise _error() from error
        if type(parsed) is not str:
            _fail()
        return parsed
    return value


def _marked(value: str) -> bool:
    return value.startswith(("&", "*", "!")) or any(
        before.isspace() and marker in "&*!" for before, marker in zip(value, value[1:])
    )


def _error() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE, "pnpm_grammar_invalid")


def _fail() -> None:
    raise _error()
