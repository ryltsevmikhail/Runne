import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2.canonical import canonical_json, validate_relative_path
from scripts.release_v2.model import FailureCodeV1, ReleaseFailure
from scripts.release_v2.submodule_snapshot import directory_fd as _directory_fd
from scripts.release_v2.submodule_snapshot import file_fd as _file_fd
from scripts.release_v2.submodule_snapshot import root_fd as _root_fd
from scripts.release_v2.submodule_snapshot import capture_gitlink


_REVISION = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class RepositorySnapshot:
    revision: str
    tree_sha256: str
    cargo_lock_sha256: str
    pnpm_lock_sha256: str

    def as_tuple(self) -> tuple[str, str, str, str]:
        return self.revision, self.tree_sha256, self.cargo_lock_sha256, self.pnpm_lock_sha256


def capture_repository(root: Path) -> RepositorySnapshot:
    try:
        with _root_fd(root) as root_fd, _directory_fd(root_fd, ".git") as git_fd:
            revision, tree_sha256, values = _capture(root_fd, git_fd, True)
            return RepositorySnapshot(revision, tree_sha256, values["Cargo.lock"], values["pnpm-lock.yaml"])
    except ReleaseFailure:
        raise
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.CANDIDATE_DIRTY, "repository_snapshot_invalid") from error


def _capture(root_fd: int, git_fd: int, require_locks: bool) -> tuple[str, str, dict[str, str]]:
    revision = _head(git_fd)
    _require_supported_git_shape(git_fd)
    entries, blobs = _head_tree(git_fd, revision, require_locks)
    _require_matching_index(git_fd, entries)
    links = _require_matching_worktree(root_fd, git_fd, entries, blobs, "", require_locks, {})
    values = {path: hashlib.sha256(blob).hexdigest() for path, blob in blobs.items()}
    return revision, _tree_digest(entries, values, links), values


def _head_tree(git_fd: int, revision: str, require_locks: bool) -> tuple[dict[str, tuple[str, str]], dict[str, bytes]]:
    entries: dict[str, tuple[str, str]] = {}
    identifiers: list[str] = []
    for item in _git(git_fd, ("ls-tree", "-r", "-z", "--full-tree", revision)).split(b"\0"):
        if not item:
            continue
        header, raw_path = item.split(b"\t", 1)
        mode, kind, identifier = header.decode("ascii", "strict").split(" ")
        path = validate_relative_path(raw_path.decode("utf-8", "strict"))
        if not _REVISION.fullmatch(identifier) or path in entries or not ((kind == "blob" and mode in ("100644", "100755")) or (kind == "commit" and mode == "160000")):
            _invalid()
        entries[path] = mode, identifier
        if kind == "blob":
            identifiers.append(identifier)
    if (require_locks and ("Cargo.lock" not in entries or "pnpm-lock.yaml" not in entries)) or not entries:
        _invalid()
    blobs = _batch_blobs(git_fd, identifiers)
    return entries, {path: blobs[identifier] for path, (mode, identifier) in entries.items() if mode != "160000"}


def _batch_blobs(git_fd: int, identifiers: list[str]) -> dict[str, bytes]:
    raw, values, position = _git(git_fd, ("cat-file", "--batch"), ("\n".join(identifiers) + "\n").encode()), {}, 0
    for identifier in identifiers:
        end = raw.find(b"\n", position)
        header = raw[position:end].decode("ascii", "strict").split(" ")
        if end < 0 or len(header) != 3 or header[0] != identifier or header[1] != "blob":
            _invalid()
        size, start = int(header[2]), end + 1
        finish = start + size
        if raw[finish:finish + 1] != b"\n":
            _invalid()
        values[identifier], position = raw[start:finish], finish + 1
    if position != len(raw):
        _invalid()
    return values


def _require_matching_index(git_fd: int, tree: dict[str, tuple[str, str]]) -> None:
    raw = _read_file(git_fd, "index")
    if len(raw) < 32 or raw[:4] != b"DIRC" or int.from_bytes(raw[4:8], "big") != 2 or hashlib.sha1(raw[:-20]).digest() != raw[-20:]:
        _invalid()
    count, position, index = int.from_bytes(raw[8:12], "big"), 12, {}
    for _ in range(count):
        if position + 62 > len(raw) - 20:
            _invalid()
        mode = f"{int.from_bytes(raw[position + 24:position + 28], 'big'):06o}"
        identifier, flags = raw[position + 40:position + 60].hex(), int.from_bytes(raw[position + 60:position + 62], "big")
        end = raw.find(b"\0", position + 62, len(raw) - 20)
        if mode not in ("100644", "100755", "160000") or flags & 0x7000 or flags & 0x4000 or end < 0:
            _invalid()
        path = validate_relative_path(raw[position + 62:end].decode("utf-8", "strict"))
        if path in index:
            _invalid()
        index[path] = mode, identifier
        position += (end - position + 8) & ~7
    while position < len(raw) - 20:
        if position + 8 > len(raw) - 20:
            _invalid()
        signature, size = raw[position:position + 4], int.from_bytes(raw[position + 4:position + 8], "big")
        if signature != b"TREE" or position + 8 + size > len(raw) - 20:
            _invalid()
        position += 8 + size
    if position != len(raw) - 20 or index != tree:
        _invalid()


def _require_matching_worktree(root_fd: int, git_fd: int, tree: dict[str, tuple[str, str]], blobs: dict[str, bytes], prefix: str, allow_gitlinks: bool, links: dict[str, str]) -> dict[str, str]:
    allowed = {(path[len(prefix) + 1:] if prefix else path).split("/", 1)[0] for path in tree if not prefix or path.startswith(prefix + "/")}
    for name in os.listdir(root_fd):
        if not prefix and name == ".git":
            continue
        path = f"{prefix}/{name}" if prefix else name
        exact, descendants = tree.get(path), any(item.startswith(path + "/") for item in tree)
        if exact and not descendants and exact[0] == "160000":
            if not allow_gitlinks:
                _invalid()
            links[path] = capture_gitlink(root_fd, git_fd, path, exact[1], lambda subroot_fd, subgit_fd: _capture(subroot_fd, subgit_fd, False)[:2])
        elif exact and not descendants:
            _require_file(root_fd, name, exact[0], blobs[path])
        elif descendants and name in allowed:
            with _directory_fd(root_fd, name) as child_fd:
                _require_matching_worktree(child_fd, git_fd, tree, blobs, path, allow_gitlinks, links)
        else:
            _invalid()
    return links


def _require_file(parent_fd: int, name: str, mode: str, expected: bytes) -> None:
    with _file_fd(parent_fd, name) as file_fd:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or bool(stat.S_IMODE(before.st_mode) & 0o111) != (mode == "100755"):
            _invalid()
        value, after = _read_fd(file_fd), os.fstat(file_fd)
        if _state(before) != _state(after):
            _mutated()
        if value != expected:
            _invalid()


def _tree_digest(entries: dict[str, tuple[str, str]], values: dict[str, str], links: dict[str, str]) -> str:
    records = [{"kind": "gitlink", "mode": mode, "path": path, "revision": identifier, "tree_sha256": links[path]} if mode == "160000" else {"kind": "blob", "mode": mode, "path": path, "sha256": values[path]} for path, (mode, identifier) in entries.items()]
    records.sort(key=lambda record: record["path"].encode("utf-8"))
    return hashlib.sha256(canonical_json(records)).hexdigest()


def _head(git_fd: int) -> str:
    value = _read_file(git_fd, "HEAD").decode("ascii", "strict").strip()
    if value.startswith("ref: refs/"):
        value = _read_ref(git_fd, value[5:]).decode("ascii", "strict").strip()
    if not _REVISION.fullmatch(value):
        _invalid()
    return value


def _read_ref(git_fd: int, reference: str) -> bytes:
    parts = reference.split("/")
    if not parts or parts[0] != "refs" or any(not part or part in (".", "..") for part in parts):
        _invalid()
    fd = os.dup(git_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return _read_file(fd, parts[-1])
    finally:
        os.close(fd)


def _require_supported_git_shape(git_fd: int) -> None:
    for name in ("commondir", "shallow"):
        if _exists(git_fd, name):
            _invalid()
    with _directory_fd(git_fd, "objects") as objects_fd:
        with _directory_fd(objects_fd, "info") as info_fd:
            if _exists(info_fd, "alternates"):
                _invalid()


def _git(git_fd: int, arguments: tuple[str, ...], input_data: bytes = b"") -> bytes:
    if not _allowed_git_arguments(arguments):
        _invalid()
    environment = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "LC_ALL": "C", "PATH": os.defpath}
    try:
        return subprocess.run(("git", "--no-pager", "--no-replace-objects", f"--git-dir=/proc/self/fd/{git_fd}", *arguments), check=True, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, pass_fds=(git_fd,)).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReleaseFailure(FailureCodeV1.CANDIDATE_DIRTY, "repository_command_failed") from error


def _read_file(parent_fd: int, name: str) -> bytes:
    with _file_fd(parent_fd, name) as fd:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            _invalid()
        value, after = _read_fd(fd), os.fstat(fd)
        if _state(before) != _state(after):
            _mutated()
        return value


def _read_fd(fd: int) -> bytes:
    values = []
    while value := os.read(fd, 1 << 20):
        values.append(value)
    return b"".join(values)


def _exists(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _state(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _allowed_git_arguments(arguments: object) -> bool:
    return type(arguments) is tuple and (arguments == ("cat-file", "--batch") or (len(arguments) == 5 and arguments[:4] == ("ls-tree", "-r", "-z", "--full-tree") and type(arguments[4]) is str and _REVISION.fullmatch(arguments[4]) is not None))


def _mutated() -> None:
    raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "repository_snapshot_changed")


def _invalid() -> None:
    raise ReleaseFailure(FailureCodeV1.CANDIDATE_DIRTY, "repository_snapshot_invalid")
