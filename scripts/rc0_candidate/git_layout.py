"""Retained descriptor model for conventional and linked Git worktrees."""

from __future__ import annotations

import fcntl
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_ENTRY = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_DARWIN_F_GETPATH = 50
_DARWIN_PATH_MAX = 1024


class GitLayoutError(ValueError):
    pass


class GitLayoutChanged(GitLayoutError):
    pass


def descriptor_state(fd: int) -> tuple[int, ...]:
    value = os.fstat(fd)
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def entry_state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def fd_path(fd: int) -> Path:
    if sys.platform == "darwin":
        raw = fcntl.fcntl(fd, _DARWIN_F_GETPATH, b"\0" * _DARWIN_PATH_MAX)
        value = os.fsdecode(raw.split(b"\0", 1)[0])
    else:
        value = os.readlink(f"/proc/self/fd/{fd}")
    if value.endswith(" (deleted)"):
        raise GitLayoutChanged("retained Git path was deleted")
    return Path(value)


def fd_reference(fd: int) -> str:
    if sys.platform == "darwin":
        return os.fspath(fd_path(fd))
    return f"/proc/self/fd/{fd}"


def open_absolute_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise GitLayoutError("Git directory path is not canonical absolute")
    descriptor = os.open("/", _DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def read_small(fd: int, limit: int = 4096) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    data = os.read(fd, limit + 1)
    if len(data) > limit:
        raise GitLayoutError("Git administrative file exceeds its bound")
    return data


def _absolute_link(base: Path, raw: bytes) -> Path:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GitLayoutError("Git administrative path is not UTF-8") from error
    if not value or "\0" in value or "\n" in value or "\r" in value:
        raise GitLayoutError("Git administrative path is malformed")
    joined = value if os.path.isabs(value) else os.path.join(base, value)
    return Path(os.path.abspath(os.path.normpath(joined)))


def _command_path(raw: bytes) -> Path:
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise GitLayoutError("Git reported path is not UTF-8") from error
    path = Path(value)
    if not path.is_absolute():
        raise GitLayoutError("Git reported path is not absolute")
    return path


@dataclass
class GitLayout:
    root_fd: int
    root_path: Path
    root_state: tuple[int, ...]
    dotgit_fd: int
    dotgit_state: tuple[int, ...]
    dotgit_bytes: bytes | None
    git_fd: int
    git_path: Path
    git_state: tuple[int, ...]
    common_fd: int
    common_path: Path
    common_state: tuple[int, ...]
    commondir_fd: int
    commondir_state: tuple[int, ...] | None
    commondir_bytes: bytes | None
    backlink_fd: int
    backlink_state: tuple[int, ...] | None
    backlink_bytes: bytes | None

    @classmethod
    def capture(cls, root_fd: int, run: Callable[..., bytes]) -> "GitLayout":
        root_path = fd_path(root_fd)
        dotgit_fd = os.open(".git", _ENTRY, dir_fd=root_fd)
        git_fd = common_fd = commondir_fd = backlink_fd = -1
        try:
            dot_state = descriptor_state(dotgit_fd)
            reported_git = _command_path(run(root_fd, "rev-parse", "--absolute-git-dir"))
            reported_common = _command_path(
                run(root_fd, "rev-parse", "--path-format=absolute", "--git-common-dir")
            )
            if stat.S_ISDIR(os.fstat(dotgit_fd).st_mode):
                dot_bytes = None
                expected_git = root_path / ".git"
                git_fd = os.dup(dotgit_fd)
            elif stat.S_ISREG(os.fstat(dotgit_fd).st_mode):
                dot_bytes = read_small(dotgit_fd)
                if not dot_bytes.startswith(b"gitdir: ") or dot_bytes.count(b"\n") != 1:
                    raise GitLayoutError(".git file grammar is invalid")
                expected_git = _absolute_link(root_path, dot_bytes[8:-1])
                git_fd = open_absolute_directory(expected_git)
            else:
                raise GitLayoutError(".git is neither a directory nor regular file")
            if reported_git != fd_path(git_fd) or reported_git != expected_git:
                raise GitLayoutError("Git directory relationship is redirected")
            try:
                commondir_fd = os.open("commondir", _ENTRY, dir_fd=git_fd)
            except FileNotFoundError:
                commondir_fd = -1
                commondir_state = None
                commondir_bytes = None
                expected_common = reported_git
            else:
                commondir_state = descriptor_state(commondir_fd)
                commondir_bytes = read_small(commondir_fd)
                if commondir_bytes != b"../..\n":
                    raise GitLayoutError("linked-worktree commondir relationship is unexpected")
                expected_common = _absolute_link(reported_git, commondir_bytes[:-1])
                if reported_git.parent.name != "worktrees" or reported_git.parent.parent != expected_common:
                    raise GitLayoutError("linked-worktree Git directory is outside its common dir")
                backlink_fd = os.open("gitdir", _ENTRY, dir_fd=git_fd)
                backlink_state = descriptor_state(backlink_fd)
                backlink_bytes = read_small(backlink_fd)
                if backlink_bytes != os.fsencode(root_path / ".git") + b"\n":
                    raise GitLayoutError("linked-worktree backlink is invalid")
            common_fd = open_absolute_directory(expected_common)
            if reported_common != fd_path(common_fd) or reported_common != expected_common:
                raise GitLayoutError("Git common directory relationship is redirected")
            return cls(
                root_fd, root_path, descriptor_state(root_fd), dotgit_fd, dot_state,
                dot_bytes, git_fd, reported_git, descriptor_state(git_fd), common_fd,
                reported_common, descriptor_state(common_fd), commondir_fd,
                commondir_state, commondir_bytes, backlink_fd,
                None if backlink_fd < 0 else descriptor_state(backlink_fd),
                None if backlink_fd < 0 else backlink_bytes,
            )
        except Exception:
            for descriptor in (backlink_fd, commondir_fd, common_fd, git_fd, dotgit_fd):
                if descriptor >= 0:
                    os.close(descriptor)
            raise

    def assert_unchanged(self) -> None:
        current_dot = os.stat(".git", dir_fd=self.root_fd, follow_symlinks=False)
        current_root = open_absolute_directory(self.root_path)
        current_git = open_absolute_directory(self.git_path)
        current_common = open_absolute_directory(self.common_path)
        try:
            states_match = (
                self.root_state == descriptor_state(self.root_fd)
                and self.root_state == descriptor_state(current_root)
                and self.dotgit_state == descriptor_state(self.dotgit_fd)
                and self.dotgit_state == entry_state(current_dot)
                and self.git_state == descriptor_state(self.git_fd)
                and self.git_state == descriptor_state(current_git)
                and self.common_state == descriptor_state(self.common_fd)
                and self.common_state == descriptor_state(current_common)
            )
            bytes_match = self.dotgit_bytes is None or read_small(self.dotgit_fd) == self.dotgit_bytes
            if self.commondir_fd >= 0:
                state = os.stat("commondir", dir_fd=self.git_fd, follow_symlinks=False)
                states_match &= self.commondir_state == entry_state(state)
                bytes_match &= read_small(self.commondir_fd) == self.commondir_bytes
            if self.backlink_fd >= 0:
                state = os.stat("gitdir", dir_fd=self.git_fd, follow_symlinks=False)
                states_match &= self.backlink_state == entry_state(state)
                bytes_match &= read_small(self.backlink_fd) == self.backlink_bytes
            if not states_match or not bytes_match:
                raise GitLayoutChanged("Git path identity changed during capture")
        finally:
            os.close(current_common)
            os.close(current_git)
            os.close(current_root)

    def close(self) -> None:
        seen: set[int] = set()
        for descriptor in (
            self.backlink_fd, self.commondir_fd, self.common_fd, self.git_fd, self.dotgit_fd
        ):
            if descriptor >= 0 and descriptor not in seen:
                seen.add(descriptor)
                os.close(descriptor)
