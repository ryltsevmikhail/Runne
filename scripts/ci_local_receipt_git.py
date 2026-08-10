"""Config-bound, byte-authoritative Git state for local input receipts."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError, digest
from scripts.rc0_candidate.git_controls import check_layout_controls
from scripts.rc0_candidate.git_inspection import _config, _open_directory
from scripts.rc0_candidate.git_layout import GitLayout, GitLayoutChanged, GitLayoutError
from scripts.rc0_candidate.git_policy import GitInspectionError
from scripts.rc0_policy.canonical import canonical_bytes

_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull, "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    "LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin",
}
_OVERRIDES = (
    "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
    "-c", "status.showUntrackedFiles=all", "-c", "diff.ignoreSubmodules=none",
    "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
)


def _run_command(
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


def _bootstrap(git: Path, root_fd: int, *arguments: str, **options) -> bytes:
    extra = options.get("extra_fds", ())
    return _run_command(
        (git, "-C", f"/proc/self/fd/{root_fd}", "--no-pager",
         "--no-replace-objects", *_OVERRIDES, *arguments),
        (root_fd, *extra),
    )


def _runner(git: Path, layout: GitLayout):
    def run(root_fd: int, *arguments: str, **options) -> bytes:
        extra = options.get("extra_fds", ())
        return _run_command(
            (git, "--no-pager", "--no-replace-objects",
             f"--git-dir=/proc/self/fd/{layout.git_fd}",
             f"--work-tree=/proc/self/fd/{layout.root_fd}",
             *_OVERRIDES, *arguments),
            (layout.root_fd, layout.git_fd, layout.common_fd, *extra),
            options.get("data", b""),
        )
    return run


def _read_fd(fd: int) -> tuple[bytes, tuple[int, ...]]:
    before = os.fstat(fd)
    values: list[bytes] = []
    while value := os.read(fd, 1 << 20):
        values.append(value)
    after = os.fstat(fd)
    state = _state(before)
    if state != _state(after) or not stat.S_ISREG(before.st_mode):
        raise LocalInputReceiptError("Git-bound file changed while read")
    return b"".join(values), state


def _state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _configuration(layout: GitLayout) -> str:
    records = []
    seen: set[tuple[int, int, str]] = set()
    for label, parent, name in (
        ("common", layout.common_fd, "config"),
        ("common-worktree", layout.common_fd, "config.worktree"),
        ("worktree", layout.git_fd, "config.worktree"),
    ):
        identity = (*_state(os.fstat(parent))[:2], name)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            fd = os.open(name, _FILE, dir_fd=parent)
        except FileNotFoundError:
            records.append({"label": label, "present": False})
            continue
        try:
            raw, state = _read_fd(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if state != _state(current):
                raise LocalInputReceiptError("Git configuration path changed")
            records.append({
                "label": label, "present": True, "sha256": digest(raw),
                "state": list(state),
            })
        finally:
            os.close(fd)
    layout_bits = {
        "dotgit": None if layout.dotgit_bytes is None else digest(layout.dotgit_bytes),
        "commondir": None if layout.commondir_bytes is None else digest(layout.commondir_bytes),
        "backlink": None if layout.backlink_bytes is None else digest(layout.backlink_bytes),
    }
    return hashlib.sha256(canonical_bytes({"files": records, "layout": layout_bits})).hexdigest()


def _entries(raw: bytes, *, index: bool) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        header, separator, raw_path = item.partition(b"\t")
        try:
            fields = header.decode("ascii").split(" ")
            if index:
                mode, oid, stage = fields
                if stage != "0":
                    raise ValueError
            else:
                mode, kind, oid = fields
                if kind not in {"blob", "commit"}:
                    raise ValueError
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise LocalInputReceiptError("Git tree or index is malformed") from error
        parts = path.split("/")
        if (
            not separator or not _OID.fullmatch(oid) or path in entries
            or not parts or any(not part or part in {".", ".."} for part in parts)
            or mode not in {"100644", "100755", "120000", "160000"}
        ):
            raise LocalInputReceiptError("Git tree or index is malformed")
        entries[path] = mode, oid
    if not entries:
        raise LocalInputReceiptError("Git tree is empty")
    return entries


def _blobs(run, entries: dict[str, tuple[str, str]]) -> dict[str, bytes]:
    identifiers = list(dict.fromkeys(oid for mode, oid in entries.values() if mode != "160000"))
    raw = run(0, "cat-file", "--batch", data=("\n".join(identifiers) + "\n").encode())
    values: dict[str, bytes] = {}
    position = 0
    for expected in identifiers:
        end = raw.find(b"\n", position)
        try:
            oid, kind, size_raw = raw[position:end].decode("ascii").split(" ")
            size = int(size_raw)
        except (UnicodeDecodeError, ValueError) as error:
            raise LocalInputReceiptError("Git object batch is malformed") from error
        start, finish = end + 1, end + 1 + size
        if end < 0 or oid != expected or kind != "blob" or raw[finish:finish + 1] != b"\n":
            raise LocalInputReceiptError("Git object batch is malformed")
        values[oid], position = raw[start:finish], finish + 1
    if position != len(raw):
        raise LocalInputReceiptError("Git object batch is malformed")
    return values


def _worktree_bytes(root_fd: int, path: str, mode: str) -> bytes:
    parts = path.split("/")
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        metadata = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if mode == "120000":
            if not stat.S_ISLNK(metadata.st_mode):
                raise LocalInputReceiptError("tracked symlink changed")
            value = os.fsencode(os.readlink(parts[-1], dir_fd=parent))
            current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            if _state(metadata) != _state(current) or _root_entry_state(root_fd, parts) != _state(current):
                raise LocalInputReceiptError("tracked symlink changed while read")
            return value
        fd = os.open(parts[-1], _FILE, dir_fd=parent)
        try:
            raw, state = _read_fd(fd)
            current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
            if (
                _state(metadata) != state or state != _state(current)
                or _root_entry_state(root_fd, parts) != state
                or executable != (mode == "100755")
            ):
                raise LocalInputReceiptError("tracked file changed while read")
            return raw
        finally:
            os.close(fd)
    except OSError as error:
        raise LocalInputReceiptError("tracked worktree path is unavailable") from error
    finally:
        os.close(parent)


def _root_entry_state(root_fd: int, parts: list[str]) -> tuple[int, ...]:
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        return _state(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))
    finally:
        os.close(parent)


def capture_repository_state(root: Path, git: Path) -> dict:
    root_fd = _open_directory(root)
    layout = None
    try:
        layout = GitLayout.capture(root_fd, lambda fd, *args, **opts: _bootstrap(git, fd, *args, **opts))
        run = _runner(git, layout)
        before = _configuration(layout)
        check_layout_controls(root_fd, layout, run, lambda fd: _config_with(run, fd))
        head = run(root_fd, "rev-parse", "HEAD").decode("ascii").strip()
        tree_oid = run(root_fd, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
        if not _OID.fullmatch(head) or not _OID.fullmatch(tree_oid):
            raise LocalInputReceiptError("source revision is malformed")
        tree = _entries(run(root_fd, "ls-tree", "-r", "-z", "--full-tree", head), index=False)
        index = _entries(run(root_fd, "ls-files", "--stage", "-z"), index=True)
        if tree != index:
            raise LocalInputReceiptError("Git index does not match HEAD")
        blobs = _blobs(run, tree)
        for path, (mode, oid) in tree.items():
            if mode != "160000" and _worktree_bytes(root_fd, path, mode) != blobs[oid]:
                raise LocalInputReceiptError("source tracked worktree bytes do not match HEAD")
        status = run(root_fd, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none")
        after = _configuration(layout)
        check_layout_controls(root_fd, layout, run, lambda fd: _config_with(run, fd))
        layout.assert_unchanged()
        if status or before != after:
            raise LocalInputReceiptError("source or Git configuration is dirty or changed")
        return {
            "source_revision": head, "source_tree": tree_oid,
            "repository_identity": {
                "worktree_dev": layout.root_state[0], "worktree_ino": layout.root_state[1],
                "git_dir_dev": layout.git_state[0], "git_dir_ino": layout.git_state[1],
            },
            "git_metadata_sha256": after,
        }
    except (GitInspectionError, GitLayoutChanged, GitLayoutError, OSError, UnicodeDecodeError) as error:
        raise LocalInputReceiptError("source identity is unavailable") from error
    finally:
        if layout is not None:
            layout.close()
        os.close(root_fd)


def _config_with(run, root_fd: int) -> tuple[tuple[str, str], ...]:
    raw = run(root_fd, "config", "--local", "--no-includes", "--null", "--list")
    entries = []
    for item in raw.split(b"\0"):
        if item:
            key, separator, value = item.partition(b"\n")
            if not separator:
                raise GitInspectionError("SOURCE_GIT_CONFIG_UNSAFE", "malformed config")
            entries.append((key.decode("utf-8").casefold(), value.decode("utf-8")))
    return tuple(entries)


def repository_location(root: Path, git: Path) -> tuple[Path, dict[str, int]]:
    state = capture_repository_state(root, git)
    root_fd = _open_directory(root)
    layout = None
    try:
        layout = GitLayout.capture(root_fd, lambda fd, *args, **opts: _bootstrap(git, fd, *args, **opts))
        return layout.git_path, state["repository_identity"]
    finally:
        if layout is not None:
            layout.close()
        os.close(root_fd)
