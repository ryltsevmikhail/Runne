import json
import unicodedata
from collections.abc import Iterable

from scripts.release_v2.model import FailureCodeV1, FailureCodeV2, ReleaseFailure


def canonical_json(value: object) -> bytes:
    try:
        _validate_json_value(value)
        payload = json.dumps(
            _sorted_json_value(value),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except ReleaseFailure:
        raise
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_value_invalid") from error
    return payload + b"\n"


def parse_canonical_json(
    raw: bytes, *, required: frozenset[str], optional: frozenset[str]
) -> dict[str, object]:
    if type(raw) is not bytes or not _valid_key_set(required) or not _valid_key_set(optional):
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_input_invalid")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_bom_rejected")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except ReleaseFailure:
        raise
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_invalid") from error
    if not isinstance(parsed, dict) or not required <= set(parsed) <= required | optional:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_keys_invalid")
    if raw != canonical_json(parsed):
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_not_canonical")
    return parsed


def sort_utf8(values: Iterable[str]) -> tuple[str, ...]:
    try:
        normalized = tuple(_validate_nfc(value) for value in values)
        return tuple(sorted(normalized, key=lambda value: value.encode("utf-8")))
    except ReleaseFailure:
        raise
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "string_list_invalid") from error


def validate_sha256(value: str) -> str:
    if type(value) is not str or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ReleaseFailure(FailureCodeV1.CHECKSUM_INVALID, "sha256_invalid")
    return value


def validate_relative_path(value: str) -> str:
    if type(value) is not str or not value or "\\" in value or value.startswith("/"):
        raise ReleaseFailure(FailureCodeV1.PATH_UNSAFE, "relative_path_invalid")
    if len(value) >= 2 and value[0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" and value[1] == ":":
        raise ReleaseFailure(FailureCodeV1.PATH_UNSAFE, "relative_path_invalid")
    value = _validate_nfc(value, FailureCodeV1.PATH_UNSAFE)
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ReleaseFailure(FailureCodeV1.PATH_UNSAFE, "path_control_character")
    if any(not part or part in {".", ".."} for part in value.split("/")):
        raise ReleaseFailure(FailureCodeV1.PATH_UNSAFE, "path_segment_invalid")
    return value


def validate_unique_relative_paths(values: Iterable[str]) -> tuple[str, ...]:
    try:
        paths = tuple(validate_relative_path(value) for value in values)
        folded = [path.casefold() for path in paths]
        if len(set(folded)) != len(folded):
            raise ReleaseFailure(FailureCodeV2.CASE_COLLISION_REJECTED, "path_case_collision")
        return paths
    except ReleaseFailure:
        raise
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.PATH_UNSAFE, "relative_paths_invalid") from error


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_duplicate_key")
        result[key] = value
    return result


def _valid_key_set(value: object) -> bool:
    return type(value) is frozenset and all(type(key) is str for key in value)


def _validate_json_value(value: object) -> None:
    if value is None or type(value) is bool or type(value) is int:
        return
    if type(value) is str:
        _validate_nfc(value)
        return
    if type(value) in (list, tuple):
        for item in value:
            _validate_json_value(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_key_invalid")
            _validate_nfc(key)
            _validate_json_value(item)
        return
    raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "json_value_invalid")


def _sorted_json_value(value: object) -> object:
    if type(value) is dict:
        return {key: _sorted_json_value(value[key]) for key in sort_utf8(value.keys())}
    if type(value) in (list, tuple):
        return [_sorted_json_value(item) for item in value]
    return value


def _validate_nfc(value: str, code: FailureCodeV1 = FailureCodeV1.MANIFEST_INVALID) -> str:
    if type(value) is not str:
        raise ReleaseFailure(code, "string_invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ReleaseFailure(code, "string_utf8_invalid") from error
    if unicodedata.normalize("NFC", value) != value:
        raise ReleaseFailure(code, "string_nfc_required")
    return encoded.decode("utf-8")
