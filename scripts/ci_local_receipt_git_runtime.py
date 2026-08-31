"""Closed Git subprocess and retained metadata helpers for receipts."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError, digest
from scripts.ci_local_receipt_runtime import _system_directories
from scripts.rc0_candidate.git_layout import GitLayout, fd_reference
from scripts.rc0_candidate.git_policy import GitInspectionError
from scripts.rc0_policy.canonical import canonical_bytes

_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull, "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    "LC_ALL": "C", "LANG": "C",
    "PATH": os.pathsep.join(os.fspath(directory) for directory in _system_directories()),
}
_OVERRIDES = (
    "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
    "-c", "status.showUntrackedFiles=all", "-c", "diff.ignoreSubmodules=none",
    "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
)


def run_command(
    command: tuple[object, ...], descriptors: tuple[int, ...], data: bytes = b""
) -> bytes:
    try:
        result = subprocess.run(
            command, check=False, input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=dict(_ENVIRONMENT), pass_fds=descriptors,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LocalInputReceiptError("hardened Git inspection failed") from error
    if result.returncode != 0:
        raise LocalInputReceiptError("hardened Git inspection failed")
    return result.stdout


def bootstrap(git: Path, root_fd: int, *arguments: str, **options) -> bytes:
    extra = options.get("extra_fds", ())
    return run_command(
        (git, "-C", fd_reference(root_fd), "--no-pager",
         "--no-replace-objects", *_OVERRIDES, *arguments),
        (root_fd, *extra),
    )


def runner(git: Path, layout: GitLayout):
    def run(root_fd: int, *arguments: str, **options) -> bytes:
        extra = options.get("extra_fds", ())
        return run_command(
            (git, "--no-pager", "--no-replace-objects",
             f"--git-dir={fd_reference(layout.git_fd)}",
             f"--work-tree={fd_reference(layout.root_fd)}",
             *_OVERRIDES, *arguments),
            (layout.root_fd, layout.git_fd, layout.common_fd, *extra),
            options.get("data", b""),
        )
    return run


def state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _read_fd(fd: int) -> tuple[bytes, tuple[int, ...]]:
    before = os.fstat(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    values: list[bytes] = []
    while value := os.read(fd, 1 << 20):
        values.append(value)
    after = os.fstat(fd)
    current = state(before)
    if current != state(after) or not stat.S_ISREG(before.st_mode):
        raise LocalInputReceiptError("Git-bound file changed while read")
    return b"".join(values), current


def configuration_digest(layout: GitLayout) -> str:
    records = []
    seen: set[tuple[int, int, str]] = set()
    for label, parent, name in (
        ("common", layout.common_fd, "config"),
        ("common-worktree", layout.common_fd, "config.worktree"),
        ("worktree", layout.git_fd, "config.worktree"),
    ):
        identity = (*state(os.fstat(parent))[:2], name)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            fd = os.open(name, _FILE, dir_fd=parent)
        except FileNotFoundError:
            records.append({"label": label, "present": False})
            continue
        try:
            raw, retained = _read_fd(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if retained != state(current):
                raise LocalInputReceiptError("Git configuration path changed")
            records.append({
                "label": label, "present": True, "sha256": digest(raw),
                "state": list(retained),
            })
        finally:
            os.close(fd)
    layout_bits = {
        "dotgit": None if layout.dotgit_bytes is None else digest(layout.dotgit_bytes),
        "commondir": None if layout.commondir_bytes is None else digest(layout.commondir_bytes),
        "backlink": None if layout.backlink_bytes is None else digest(layout.backlink_bytes),
    }
    return hashlib.sha256(canonical_bytes({"files": records, "layout": layout_bits})).hexdigest()


def config_entries(run, root_fd: int) -> tuple[tuple[str, str], ...]:
    raw = run(root_fd, "config", "--local", "--no-includes", "--null", "--list")
    entries = []
    for item in raw.split(b"\0"):
        if item:
            key, separator, value = item.partition(b"\n")
            if not separator:
                raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "malformed config")
            entries.append((key.decode("utf-8").casefold(), value.decode("utf-8")))
    return tuple(entries)
