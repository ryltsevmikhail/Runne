"""Repository-tree walking that preserves tracked policy artifacts."""
from functools import lru_cache
import os
import subprocess


IGNORED_TREE_NAMES = {".git", ".worktrees", "node_modules", "target"}
IGNORED_TREE_PREFIXES = ("target-",)


@lru_cache
def _tracked_tree(repository_root):
    result = subprocess.run(
        ["git", "-C", repository_root, "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    files = frozenset(
        os.fsdecode(path) for path in result.stdout.split(b"\0") if path
    )
    directories = set()
    for path in files:
        directory = path.rpartition("/")[0]
        while directory:
            directories.add(directory)
            directory = directory.rpartition("/")[0]
    return files, frozenset(directories)


def _superpowers_path(relative):
    relative = relative.replace("\\", "/").replace(os.sep, "/")
    return relative == ".superpowers" or relative.startswith(".superpowers/")


def _git_relative(path, repository_root):
    return os.path.relpath(path, repository_root).replace("\\", "/").replace(os.sep, "/")


def walk_repository_files(root, repository_root, suffixes=None, excluded_roots=()):
    """Yield files while skipping generated trees and untracked agent scratch."""
    tracked_files, tracked_directories = _tracked_tree(os.path.abspath(repository_root))
    excluded = {os.path.normpath(path) for path in excluded_roots}
    for current_root, directories, files in os.walk(root):
        directories[:] = [
            directory for directory in directories
            if directory not in IGNORED_TREE_NAMES
            and not directory.startswith(IGNORED_TREE_PREFIXES)
            and os.path.normpath(os.path.join(current_root, directory)) not in excluded
            and (
                not _superpowers_path(_git_relative(os.path.join(current_root, directory), repository_root))
                or _git_relative(os.path.join(current_root, directory), repository_root) in tracked_directories
            )
        ]
        for filename in files:
            path = os.path.join(current_root, filename)
            relative = _git_relative(path, repository_root)
            if _superpowers_path(relative) and relative not in tracked_files:
                continue
            if suffixes is None or filename.endswith(suffixes):
                yield path
