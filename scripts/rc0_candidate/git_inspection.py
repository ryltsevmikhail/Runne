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

from .git_controls import check_layout_controls, check_submodule_relationship
from .git_layout import (
    GitLayout,
    GitLayoutChanged,
    GitLayoutError,
    descriptor_state,
    entry_state,
    fd_reference,
)
from .git_policy import GitInspectionError

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


def _run(
    root_fd: int, *arguments: str, check: bool = True,
    extra_fds: tuple[int, ...] = (),
) -> bytes:
    result = subprocess.run(
        (_GIT, "-C", fd_reference(root_fd), "--no-pager", "--no-replace-objects", *arguments),
        check=False,
        capture_output=True,
        env=dict(_ENVIRONMENT),
        pass_fds=(root_fd, *extra_fds),
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
    layout: GitLayout | None = None
    try:
        layout = GitLayout.capture(root_fd, _run)
        check_layout_controls(root_fd, layout, _run, _config)
        layout.assert_unchanged()
    except (GitLayoutError, OSError) as error:
        raise GitInspectionError("SOURCE_GIT_INSPECTION_FAILED", "stable Git layout is unavailable") from error
    finally:
        if layout is not None:
            layout.close()
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
    layout: GitLayout | None = None
    sub_layout: GitLayout | None = None
    modules_fd = config_fd = sub_root_fd = -1
    try:
        layout = GitLayout.capture(root_fd, _run)
        sub_root_fd = os.open("upstream/opencode", _DIRECTORY, dir_fd=root_fd)
        sub_root_state = descriptor_state(sub_root_fd)
        sub_path_state = entry_state(
            os.stat("upstream/opencode", dir_fd=root_fd, follow_symlinks=False)
        )
        sub_layout = GitLayout.capture(sub_root_fd, _run)
        check_submodule_relationship(layout, sub_layout)
        config_fd = os.open("config", _FILE, dir_fd=layout.common_fd)
        modules_fd = os.open(".gitmodules", _FILE, dir_fd=root_fd)
        config_state = _state(os.fstat(config_fd))
        modules_state = _state(os.fstat(modules_fd))
        if not stat.S_ISREG(os.fstat(modules_fd).st_mode):
            raise GitInspectionError("SOURCE_GITMODULES_POLICY_MISMATCH", ".gitmodules is not regular")
        check_layout_controls(root_fd, layout, _run, _config)
        check_layout_controls(sub_root_fd, sub_layout, _run, _config)
        initial = _live(root_fd)
        retained_config = _read_retained(config_fd)
        retained_modules = _read_retained(modules_fd)
        if mutation_hook is not None:
            mutation_hook("before-final-recheck", Path(repository))
        check_layout_controls(root_fd, layout, _run, _config)
        check_layout_controls(sub_root_fd, sub_layout, _run, _config)
        final = _live(root_fd)
        config_again = _read_retained(config_fd)
        retained_again = _read_retained(modules_fd)
        path_state = _state(os.stat(".gitmodules", dir_fd=root_fd, follow_symlinks=False))
        config_path_state = _state(
            os.stat("config", dir_fd=layout.common_fd, follow_symlinks=False)
        )
        current_sub_state = entry_state(
            os.stat("upstream/opencode", dir_fd=root_fd, follow_symlinks=False)
        )
        layout.assert_unchanged()
        sub_layout.assert_unchanged()
        if (
            initial != final
            or retained_modules != retained_again
            or retained_config != config_again
            or retained_modules != initial[6][3]
            or modules_state != _state(os.fstat(modules_fd))
            or modules_state != path_state
            or config_state != _state(os.fstat(config_fd))
            or config_state != config_path_state
            or sub_root_state != descriptor_state(sub_root_fd)
            or sub_path_state != current_sub_state
        ):
            raise GitInspectionError("SOURCE_SNAPSHOT_CHANGED", "Git/filesystem snapshot changed during capture")
        if initial[3]:
            raise GitInspectionError("SOURCE_DIRTY", "tracked, untracked or submodule state is dirty")
        head, parents, tree, _status, _config_entries, origins, bindings = initial
        return GitSnapshot(head, parents, tree, origins, bindings[0], retained_modules, bindings[2], bindings[1])
    except GitLayoutChanged as error:
        raise GitInspectionError("SOURCE_SNAPSHOT_CHANGED", "Git/filesystem snapshot changed during capture") from error
    except GitInspectionError:
        raise
    except (GitLayoutError, OSError, UnicodeDecodeError, ValueError) as error:
        raise GitInspectionError("SOURCE_GIT_INSPECTION_FAILED", "stable Git snapshot is unavailable") from error
    finally:
        if sub_layout is not None:
            sub_layout.close()
        if layout is not None:
            layout.close()
        for descriptor in (modules_fd, config_fd, sub_root_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)
