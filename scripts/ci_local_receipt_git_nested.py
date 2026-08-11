"""Retained validation for first-level receipt gitlinks."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError
from scripts.ci_local_receipt_git_runtime import (
    bootstrap,
    config_entries,
    configuration_digest,
    runner,
    state,
)
from scripts.ci_local_receipt_git_tree import capture_tree, require_clean_status
from scripts.rc0_candidate.git_controls import check_layout_controls
from scripts.rc0_candidate.git_layout import GitLayout, descriptor_state, fd_path

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_relative_directory(root_fd: int, path: str) -> int:
    descriptor = os.dup(root_fd)
    try:
        for part in path.split("/"):
            child = os.open(part, _DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _entry_state(root_fd: int, path: str) -> tuple[int, ...]:
    descriptor = os.dup(root_fd)
    parts = path.split("/")
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return state(os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False))
    finally:
        os.close(descriptor)


@dataclass
class NestedRepository:
    path: str
    expected_head: str
    super_root_fd: int
    root_fd: int
    path_state: tuple[int, ...]
    layout: GitLayout
    git: Path
    initial: dict

    @classmethod
    def capture(
        cls, super_layout: GitLayout, path: str, expected_head: str, git: Path
    ) -> "NestedRepository":
        root_fd = _open_relative_directory(super_layout.root_fd, path)
        layout = None
        try:
            retained = descriptor_state(root_fd)
            if retained != _entry_state(super_layout.root_fd, path):
                raise LocalInputReceiptError("gitlink path changed while opened")
            expected_root = super_layout.root_path / Path(path)
            if fd_path(root_fd) != expected_root:
                raise LocalInputReceiptError("gitlink worktree relationship is redirected")
            layout = GitLayout.capture(
                root_fd, lambda fd, *args, **opts: bootstrap(git, fd, *args, **opts)
            )
            _require_relationship(super_layout, layout, path)
            nested = cls(path, expected_head, super_layout.root_fd, root_fd,
                         retained, layout, git, {})
            nested.initial = nested._inspect()
            return nested
        except Exception:
            if layout is not None:
                layout.close()
            os.close(root_fd)
            raise

    def _inspect(self) -> dict:
        run = runner(self.git, self.layout)
        before = configuration_digest(self.layout)
        check_layout_controls(
            self.root_fd, self.layout, run,
            lambda fd: config_entries(run, fd),
        )
        tree = capture_tree(run, self.root_fd, self.expected_head)
        if tree.gitlinks:
            raise LocalInputReceiptError("nested gitlinks are unsupported")
        require_clean_status(run, self.root_fd)
        after = configuration_digest(self.layout)
        check_layout_controls(
            self.root_fd, self.layout, run,
            lambda fd: config_entries(run, fd),
        )
        self.layout.assert_unchanged()
        if before != after:
            raise LocalInputReceiptError("nested Git configuration changed")
        return {
            "path": self.path, "head": tree.head, "tree": tree.tree_oid,
            "source_sha256": tree.source_sha256, "git_metadata_sha256": after,
            "repository_identity": {
                "worktree_dev": self.layout.root_state[0],
                "worktree_ino": self.layout.root_state[1],
                "git_dir_dev": self.layout.git_state[0],
                "git_dir_ino": self.layout.git_state[1],
                "common_dir_dev": self.layout.common_state[0],
                "common_dir_ino": self.layout.common_state[1],
            },
        }

    def finish(self) -> dict:
        if (
            self.path_state != descriptor_state(self.root_fd)
            or self.path_state != _entry_state(self.super_root_fd, self.path)
            or self.initial != self._inspect()
        ):
            raise LocalInputReceiptError("nested repository changed during capture")
        return self.initial

    def close(self) -> None:
        self.layout.close()
        os.close(self.root_fd)


def _require_relationship(super_layout: GitLayout, layout: GitLayout, path: str) -> None:
    allowed = {
        super_layout.git_path / "modules" / Path(path),
        super_layout.common_path / "modules" / Path(path),
    }
    if (
        layout.dotgit_bytes is None
        or layout.git_path not in allowed
        or layout.common_path != layout.git_path
    ):
        raise LocalInputReceiptError("gitlink Git directory relationship is invalid")


class NestedRepositories:
    def __init__(self, repositories: list[NestedRepository]):
        self.repositories = repositories

    @classmethod
    def capture(
        cls, super_layout: GitLayout, links: tuple[tuple[str, str], ...], git: Path
    ) -> "NestedRepositories":
        repositories: list[NestedRepository] = []
        root_identities = {super_layout.root_state[:2]}
        git_identities = {super_layout.git_state[:2], super_layout.common_state[:2]}
        try:
            for path, expected_head in sorted(links):
                nested = NestedRepository.capture(super_layout, path, expected_head, git)
                root_identity = nested.layout.root_state[:2]
                nested_git = {
                    nested.layout.git_state[:2], nested.layout.common_state[:2]
                }
                if root_identity in root_identities or nested_git & git_identities:
                    nested.close()
                    raise LocalInputReceiptError("duplicate or cyclic gitlink identity")
                root_identities.add(root_identity)
                git_identities.update(nested_git)
                repositories.append(nested)
            return cls(repositories)
        except Exception:
            for nested in repositories:
                nested.close()
            raise

    def finish(self) -> list[dict]:
        return [nested.finish() for nested in self.repositories]

    def close(self) -> None:
        for nested in reversed(self.repositories):
            nested.close()
