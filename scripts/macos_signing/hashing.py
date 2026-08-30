import hashlib
from pathlib import Path


def sha256_bytes(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise ValueError("value must be bytes")
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not isinstance(path, Path):
        raise ValueError("path must be a Path")
    return sha256_bytes(path.read_bytes())
