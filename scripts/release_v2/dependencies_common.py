import tomllib
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from scripts.release_v2.model import FailureCodeV1, ReleaseFailure


def fail(detail: str) -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE, detail)


def read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise fail("dependency_input_unavailable") from error


def toml(raw: bytes) -> dict[str, object]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except Exception as error:
        raise fail("cargo_lock_invalid") from error
    if type(value) is not dict:
        raise fail("cargo_lock_invalid")
    return value


def strings(value: object) -> tuple[str, ...]:
    if type(value) is not list or not all(type(item) is str for item in value):
        raise fail("dependency_list_invalid")
    return tuple(value)


def string(value: object) -> str:
    if type(value) is not str or not value:
        raise fail("dependency_value_invalid")
    return value


def public_locator(value: str) -> str:
    parsed = urlsplit(value)
    if "@" in parsed.netloc or parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment or any(character.isspace() for character in value):
        raise fail("dependency_locator_invalid")
    return urlunsplit(("https", parsed.hostname.lower() + (f":{parsed.port}" if parsed.port else ""), parsed.path.rstrip("/"), "", ""))
