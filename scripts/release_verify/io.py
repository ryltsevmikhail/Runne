import hashlib
import json
import pathlib
import re
import unicodedata

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"

def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result

def read_json(path):
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("BOM is not allowed")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    if raw != canonical(value):
        raise ValueError("JSON is not canonical")
    return value

def safe_path(value):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = pathlib.PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)

def exact_fields(value, fields):
    return isinstance(value, dict) and set(value) == set(fields)

def valid_hex(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None

def canonical_identity(value):
    if not isinstance(value, str):
        return None
    normalized = unicodedata.normalize("NFC", value).strip().casefold()
    return normalized or None

def candidate_file_for(candidate_root, relative):
    if not safe_path(relative):
        raise ValueError("unsafe candidate path")
    path = candidate_root.joinpath(*pathlib.PurePosixPath(relative).parts)
    if not path.is_file() or candidate_root not in path.resolve().parents:
        raise ValueError("candidate file is missing")
    return path
