"""Closed-environment Git inspection for local RC0 fixtures."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .git_policy import unsafe_config

_SHA = re.compile(r"[0-9a-f]{40}")
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "LC_ALL": "C",
    "LANG": "C",
    "PATH": os.defpath,
}

class GitInspectionError(ValueError):
    def __init__(self, reason: str, diagnostic: str):
        super().__init__(diagnostic)
        self.reason = reason
        self.diagnostic = diagnostic


@dataclass(frozen=True)
class GitSnapshot:
    head: str
    parents: tuple[str, ...]
    tree_oid: str
    origin_urls: tuple[str, ...]
    gitmodules_blob_oid: str
    gitmodules_bytes: bytes
    gitmodules_sha256: str
    gitlink_oid: str


def _trusted_git() -> str:
    for candidate in ("/usr/bin/git", "/bin/git"):
        try:
            resolved = Path(candidate).resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_mode & 0o111
            and not metadata.st_mode & 0o022
        ):
            return os.fspath(resolved)
    raise RuntimeError("trusted system Git executable is unavailable")


_GIT = _trusted_git()


def _open_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise GitInspectionError("SOURCE_PATH_UNSAFE", "repository path must be absolute")
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


def _run(root_fd: int, *arguments: str, check: bool = True) -> bytes:
    result = subprocess.run(
        (_GIT, "-C", f"/proc/self/fd/{root_fd}", "--no-pager", "--no-replace-objects", *arguments),
        check=False,
        capture_output=True,
        env=dict(_ENVIRONMENT),
        pass_fds=(root_fd,),
        timeout=30,
    )
    if check and result.returncode != 0:
        raise GitInspectionError("SOURCE_GIT_INSPECTION_FAILED", "trusted local Git command failed")
    return result.stdout


def run_repository_git(repository: Path, *arguments: str, check: bool = True) -> bytes:
    root_fd = _open_directory(Path(repository))
    try:
        return _run(root_fd, *arguments, check=check)
    finally:
        os.close(root_fd)


def validate_repository_controls(repository: Path) -> None:
    root_fd = _open_directory(Path(repository))
    git_fd = -1
    try:
        git_fd = os.open(".git", _DIRECTORY, dir_fd=root_fd)
        if unsafe_config(_config(root_fd)):
            raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "local Git config contains forbidden controls")
        objects_fd = os.open("objects", _DIRECTORY, dir_fd=git_fd)
        try:
            _check_object_directory(objects_fd)
        finally:
            os.close(objects_fd)
    finally:
        if git_fd >= 0:
            os.close(git_fd)
        os.close(root_fd)


def _state(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _read_retained(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(fd, 1 << 20):
        chunks.append(chunk)
    return b"".join(chunks)


def _config(root_fd: int) -> tuple[tuple[str, str], ...]:
    raw = _run(root_fd, "config", "--local", "--no-includes", "--null", "--list")
    entries: list[tuple[str, str]] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        key, separator, value = item.partition(b"\n")
        if not separator:
            raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "local Git config is malformed")
        try:
            entries.append((key.decode("utf-8").casefold(), value.decode("utf-8")))
        except UnicodeDecodeError as error:
            raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "local Git config is not UTF-8") from error
    return tuple(entries)


def _exists(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _check_object_directory(objects_fd: int) -> None:
    try:
        info_fd = os.open("info", _DIRECTORY, dir_fd=objects_fd)
        try:
            if any(_exists(info_fd, name) for name in ("alternates", "http-alternates")):
                raise GitInspectionError("SOURCE_GIT_OBJECT_STORE_UNSAFE", "Git object alternates are forbidden")
        finally:
            os.close(info_fd)
    except FileNotFoundError:
        pass
    try:
        pack_fd = os.open("pack", _DIRECTORY, dir_fd=objects_fd)
        try:
            if any(name.endswith(".promisor") for name in os.listdir(pack_fd)):
                raise GitInspectionError("SOURCE_GIT_OBJECT_STORE_UNSAFE", "promisor object packs are forbidden")
        finally:
            os.close(pack_fd)
    except FileNotFoundError:
        pass


def _check_object_stores(root_fd: int, git_fd: int) -> None:
    objects_fd = os.open("objects", _DIRECTORY, dir_fd=git_fd)
    try:
        _check_object_directory(objects_fd)
    finally:
        os.close(objects_fd)
    fd = os.dup(root_fd)
    try:
        for part in ("upstream", "opencode", ".git", "objects"):
            child = os.open(part, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        _check_object_directory(fd)
    finally:
        os.close(fd)


def _check_repository_controls(root_fd: int, git_fd: int) -> None:
    if unsafe_config(_config(root_fd)):
        raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "local Git config contains forbidden controls")
    _check_object_stores(root_fd, git_fd)
    submodule_fd = os.open("upstream/opencode", _DIRECTORY, dir_fd=root_fd)
    try:
        if unsafe_config(_config(submodule_fd)):
            raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "submodule Git config contains forbidden controls")
    finally:
        os.close(submodule_fd)


def _tree_bindings(root_fd: int, revision: str) -> tuple[str, str, str, bytes]:
    raw = _run(root_fd, "ls-tree", "-z", revision, "--", ".gitmodules", "upstream/opencode")
    entries: dict[str, tuple[str, str, str]] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, separator, raw_path = item.partition(b"\t")
        try:
            mode, kind, oid = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise GitInspectionError("SOURCE_RAW_CURRENT_MISMATCH", "raw tree entry is malformed") from error
        if not separator or not _SHA.fullmatch(oid) or path in entries:
            raise GitInspectionError("SOURCE_RAW_CURRENT_MISMATCH", "raw tree entry is malformed")
        entries[path] = mode, kind, oid
    modules = entries.get(".gitmodules")
    gitlink = entries.get("upstream/opencode")
    if not modules or modules[:2] != ("100644", "blob") or not gitlink or gitlink[:2] != ("160000", "commit"):
        raise GitInspectionError("SOURCE_RAW_CURRENT_MISMATCH", "required raw tree bindings are absent")
    blob = _run(root_fd, "cat-file", "blob", modules[2])
    return modules[2], gitlink[2], hashlib.sha256(blob).hexdigest(), blob


def _live(root_fd: int) -> tuple[str, tuple[str, ...], str, bytes, tuple[tuple[str, str], ...], tuple[str, ...], tuple[str, str, str, bytes]]:
    head = _run(root_fd, "rev-parse", "HEAD").decode("ascii").strip()
    tree = _run(root_fd, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    parents = tuple(_run(root_fd, "show", "-s", "--format=%P", "HEAD").decode("ascii").split())
    status = _run(root_fd, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none")
    config = _config(root_fd)
    origins = tuple(value for key, value in config if key == "remote.origin.url")
    return head, parents, tree, status, config, origins, _tree_bindings(root_fd, head)


def capture_source_snapshot(
    repository: Path, mutation_hook: Callable[[str, Path], None] | None = None
) -> GitSnapshot:
    root_fd = _open_directory(Path(repository))
    git_fd = modules_fd = config_fd = -1
    try:
        root_state = _state(os.fstat(root_fd))
        git_fd = os.open(".git", _DIRECTORY, dir_fd=root_fd)
        git_state = _state(os.fstat(git_fd))
        config_fd = os.open("config", _FILE, dir_fd=git_fd)
        modules_fd = os.open(".gitmodules", _FILE, dir_fd=root_fd)
        config_state = _state(os.fstat(config_fd))
        modules_state = _state(os.fstat(modules_fd))
        if not stat.S_ISREG(os.fstat(modules_fd).st_mode):
            raise GitInspectionError("SOURCE_GITMODULES_POLICY_MISMATCH", ".gitmodules is not regular")
        _check_repository_controls(root_fd, git_fd)
        initial = _live(root_fd)
        retained_config = _read_retained(config_fd)
        retained_modules = _read_retained(modules_fd)
        if mutation_hook is not None:
            mutation_hook("before-final-recheck", Path(repository))
        _check_repository_controls(root_fd, git_fd)
        final = _live(root_fd)
        config_again = _read_retained(config_fd)
        retained_again = _read_retained(modules_fd)
        path_state = _state(os.stat(".gitmodules", dir_fd=root_fd, follow_symlinks=False))
        config_path_state = _state(os.stat("config", dir_fd=git_fd, follow_symlinks=False))
        if (
            initial != final
            or retained_modules != retained_again
            or retained_config != config_again
            or retained_modules != initial[6][3]
            or modules_state != _state(os.fstat(modules_fd))
            or modules_state != path_state
            or config_state != _state(os.fstat(config_fd))
            or config_state != config_path_state
            or git_state != _state(os.fstat(git_fd))
            or root_state != _state(os.fstat(root_fd))
        ):
            raise GitInspectionError("SOURCE_SNAPSHOT_CHANGED", "Git/filesystem snapshot changed during capture")
        if initial[3]:
            raise GitInspectionError("SOURCE_DIRTY", "tracked, untracked or submodule state is dirty")
        head, parents, tree, _status, _config_entries, origins, bindings = initial
        return GitSnapshot(head, parents, tree, origins, bindings[0], retained_modules, bindings[2], bindings[1])
    except GitInspectionError:
        raise
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise GitInspectionError("SOURCE_GIT_INSPECTION_FAILED", "stable Git snapshot is unavailable") from error
    finally:
        for descriptor in (modules_fd, config_fd, git_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)
