import os
import stat
from pathlib import Path
from typing import Callable

from scripts.release_v2.canonical import validate_relative_path
from scripts.release_v2.model import FailureCodeV1, ReleaseFailure


_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class Fd:
    def __init__(self, value: int) -> None:
        self.value = value

    def __enter__(self) -> int:
        return self.value

    def __exit__(self, *unused: object) -> None:
        os.close(self.value)


def root_fd(root: object) -> Fd:
    if not isinstance(root, Path) or not root.is_absolute():
        _invalid()
    fd = os.open("/", _DIRECTORY)
    try:
        for name in root.parts[1:]:
            next_fd = os.open(name, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return Fd(fd)
    except Exception:
        os.close(fd)
        raise


def directory_fd(parent_fd: int, name: str) -> Fd:
    return Fd(os.open(name, _DIRECTORY, dir_fd=parent_fd))


def file_fd(parent_fd: int, name: str) -> Fd:
    return Fd(os.open(name, _FILE, dir_fd=parent_fd))


def capture_gitlink(parent_fd: int, super_git_fd: int, path: str, revision: str, capture: Callable[[int, int], tuple[str, str]]) -> str:
    parts = validate_relative_path(path).split("/")
    expected = "../" * len(parts) + ".git/modules/" + path
    with directory_fd(parent_fd, parts[-1]) as worktree_fd:
        if _read_file(worktree_fd, ".git") != f"gitdir: {expected}\n".encode():
            _invalid()
        with _module_git_fd(super_git_fd, parts) as module_git_fd:
            head, tree_sha256 = capture(worktree_fd, module_git_fd)
    if head != revision:
        _invalid()
    return tree_sha256


def _module_git_fd(super_git_fd: int, parts: list[str]) -> Fd:
    fd = os.dup(super_git_fd)
    try:
        for name in ("modules", *parts):
            next_fd = os.open(name, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return Fd(fd)
    except Exception:
        os.close(fd)
        raise


def _read_file(parent_fd: int, name: str) -> bytes:
    with file_fd(parent_fd, name) as fd:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            _invalid()
        value, after = _read_fd(fd), os.fstat(fd)
        if _state(before) != _state(after):
            raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "repository_snapshot_changed")
        return value


def _read_fd(fd: int) -> bytes:
    values = []
    while value := os.read(fd, 1 << 20):
        values.append(value)
    return b"".join(values)


def _state(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _invalid() -> None:
    raise ReleaseFailure(FailureCodeV1.CANDIDATE_DIRTY, "repository_snapshot_invalid")
