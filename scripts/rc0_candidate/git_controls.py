"""Closed configuration and object-store controls for retained Git layouts."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from .git_layout import GitLayout
from .git_policy import GitInspectionError, unsafe_config

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _parse_config(raw: bytes) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        key, separator, value = item.partition(b"\n")
        if not separator:
            raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "Git config is malformed")
        try:
            entries.append((key.decode("utf-8").casefold(), value.decode("utf-8")))
        except UnicodeDecodeError as error:
            raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "Git config is not UTF-8") from error
    return tuple(entries)


def _config_file(root_fd: int, descriptor: int, run: Callable[..., bytes]):
    raw = run(
        root_fd, "config", "--file", f"/proc/self/fd/{descriptor}", "--no-includes",
        "--null", "--list", extra_fds=(descriptor,),
    )
    return _parse_config(raw)


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
                raise GitInspectionError(
                    "SOURCE_GIT_OBJECT_STORE_UNSAFE", "Git object alternates are forbidden"
                )
        finally:
            os.close(info_fd)
    except FileNotFoundError:
        pass
    try:
        pack_fd = os.open("pack", _DIRECTORY, dir_fd=objects_fd)
        try:
            if any(name.endswith(".promisor") for name in os.listdir(pack_fd)):
                raise GitInspectionError(
                    "SOURCE_GIT_OBJECT_STORE_UNSAFE", "promisor object packs are forbidden"
                )
        finally:
            os.close(pack_fd)
    except FileNotFoundError:
        pass


def _unsafe_for_layout(entries: tuple[tuple[str, str], ...], layout: GitLayout) -> bool:
    for key, value in entries:
        if key == "core.worktree":
            joined = value if os.path.isabs(value) else os.path.join(layout.git_path, value)
            if Path(os.path.abspath(os.path.normpath(joined))) != layout.root_path:
                return True
        elif unsafe_config(((key, value),)):
            return True
    return False


def _check_admin_directory(
    root_fd: int, admin_fd: int, objects_required: bool, run: Callable[..., bytes],
    layout: GitLayout,
) -> None:
    for name in ("config", "config.worktree"):
        try:
            descriptor = os.open(name, _FILE, dir_fd=admin_fd)
        except FileNotFoundError:
            continue
        try:
            if _unsafe_for_layout(_config_file(root_fd, descriptor, run), layout):
                raise GitInspectionError(
                    "SOURCE_GIT_CONFIG_UNSAFE", "Git administrative config is unsafe"
                )
        finally:
            os.close(descriptor)
    try:
        objects_fd = os.open("objects", _DIRECTORY, dir_fd=admin_fd)
    except FileNotFoundError:
        if objects_required:
            raise GitInspectionError(
                "SOURCE_GIT_OBJECT_STORE_UNSAFE", "common Git object store is absent"
            )
        return
    try:
        _check_object_directory(objects_fd)
    finally:
        os.close(objects_fd)


def check_layout_controls(
    root_fd: int, layout: GitLayout, run: Callable[..., bytes],
    config_reader: Callable[[int], tuple[tuple[str, str], ...]],
) -> None:
    if _unsafe_for_layout(config_reader(root_fd), layout):
        raise GitInspectionError(
            "SOURCE_GIT_CONFIG_UNSAFE", "local Git config contains forbidden controls"
        )
    _check_admin_directory(root_fd, layout.common_fd, True, run, layout)
    if layout.git_state != layout.common_state:
        _check_admin_directory(root_fd, layout.git_fd, False, run, layout)


def check_submodule_relationship(super_layout: GitLayout, sub_layout: GitLayout) -> None:
    if sub_layout.dotgit_bytes is None:
        return
    suffix = Path("modules/upstream/opencode")
    allowed = (super_layout.git_path / suffix, super_layout.common_path / suffix)
    if sub_layout.git_path not in allowed or sub_layout.common_path != sub_layout.git_path:
        raise GitInspectionError(
            "SOURCE_GIT_INSPECTION_FAILED", "submodule Git directory relationship is redirected"
        )
