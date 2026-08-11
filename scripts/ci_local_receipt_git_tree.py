"""Direct tree, index, and worktree-byte validation for receipt Git state."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass

from scripts.ci_local_receipt_common import LocalInputReceiptError
from scripts.ci_local_receipt_git_runtime import state

_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


@dataclass(frozen=True)
class TreeSnapshot:
    head: str
    tree_oid: str
    gitlinks: tuple[tuple[str, str], ...]
    source_sha256: str


def source_digest(entries: dict[str, tuple[str, str]]) -> str:
    hasher = hashlib.sha256()
    for path in sorted(entries, key=lambda value: value.encode("utf-8")):
        mode, oid = entries[path]
        for value in (path.encode("utf-8"), mode.encode("ascii"), oid.encode("ascii")):
            hasher.update(len(value).to_bytes(8, "big"))
            hasher.update(value)
    return hasher.hexdigest()


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
                if (mode == "160000") != (kind == "commit"):
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
        if end < 0:
            raise LocalInputReceiptError("Git object batch is malformed")
        try:
            oid, kind, size_raw = raw[position:end].decode("ascii").split(" ")
            size = int(size_raw)
        except (UnicodeDecodeError, ValueError) as error:
            raise LocalInputReceiptError("Git object batch is malformed") from error
        start, finish = end + 1, end + 1 + size
        if oid != expected or kind != "blob" or raw[finish:finish + 1] != b"\n":
            raise LocalInputReceiptError("Git object batch is malformed")
        values[oid], position = raw[start:finish], finish + 1
    if position != len(raw):
        raise LocalInputReceiptError("Git object batch is malformed")
    return values


def _read_fd(fd: int) -> tuple[bytes, tuple[int, ...]]:
    before = os.fstat(fd)
    values: list[bytes] = []
    while value := os.read(fd, 1 << 20):
        values.append(value)
    after = os.fstat(fd)
    retained = state(before)
    if retained != state(after) or not stat.S_ISREG(before.st_mode):
        raise LocalInputReceiptError("tracked file changed while read")
    return b"".join(values), retained


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
            if state(metadata) != state(current) or _root_entry_state(root_fd, parts) != state(current):
                raise LocalInputReceiptError("tracked symlink changed while read")
            return value
        fd = os.open(parts[-1], _FILE, dir_fd=parent)
        try:
            raw, retained = _read_fd(fd)
            current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
            if (
                state(metadata) != retained or retained != state(current)
                or _root_entry_state(root_fd, parts) != retained
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
        return state(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False))
    finally:
        os.close(parent)


def capture_tree(run, root_fd: int, expected_head: str | None = None) -> TreeSnapshot:
    head = run(root_fd, "rev-parse", "HEAD").decode("ascii").strip()
    tree_oid = run(root_fd, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if not _OID.fullmatch(head) or not _OID.fullmatch(tree_oid) or (
        expected_head is not None and head != expected_head
    ):
        raise LocalInputReceiptError("source revision is malformed or mismatched")
    tree = _entries(run(root_fd, "ls-tree", "-r", "-z", "--full-tree", head), index=False)
    index = _entries(run(root_fd, "ls-files", "--stage", "-z"), index=True)
    if tree != index:
        raise LocalInputReceiptError("Git index does not match HEAD")
    blobs = _blobs(run, tree)
    for path, (mode, oid) in tree.items():
        if mode != "160000" and _worktree_bytes(root_fd, path, mode) != blobs[oid]:
            raise LocalInputReceiptError("source tracked worktree bytes do not match HEAD")
    return TreeSnapshot(
        head, tree_oid,
        tuple((path, oid) for path, (mode, oid) in tree.items() if mode == "160000"),
        source_digest(tree),
    )


def require_clean_status(run, root_fd: int) -> None:
    status = run(
        root_fd, "status", "--porcelain=v1", "-z", "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        raise LocalInputReceiptError("source or nested repository is dirty")
