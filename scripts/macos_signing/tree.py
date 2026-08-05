import hashlib
import stat
from pathlib import Path


def tree_sha256(root: Path) -> str:
    if not isinstance(root, Path) or root.is_symlink() or not root.is_dir():
        raise ValueError("invalid candidate root")
    root_path = root.resolve(strict=True)
    records = _records(root_path, root_path)
    return hashlib.sha256("".join(sorted(records)).encode()).hexdigest()


def _records(root: Path, directory: Path) -> list[str]:
    records: list[str] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        relative = path.relative_to(root).as_posix()
        information = path.lstat()
        if stat.S_ISDIR(information.st_mode):
            if path.is_symlink():
                raise ValueError("directory symlink")
            records.extend(_records(root, path))
            records.append(f"D\0{relative}\n")
        elif stat.S_ISREG(information.st_mode):
            records.append(f"F\0{relative}\0{_sha256(path.read_bytes())}\n")
        elif stat.S_ISLNK(information.st_mode):
            records.append(f"L\0{relative}\0{_safe_target(root, path)}\n")
        else:
            raise ValueError("special candidate entry")
    return records


def _safe_target(root: Path, path: Path) -> str:
    target = path.readlink()
    if target.is_absolute():
        raise ValueError("absolute symlink")
    try:
        (path.parent / target).resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        raise ValueError("escaping symlink") from None
    return target.as_posix()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
