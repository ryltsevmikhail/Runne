"""Config-bound, byte-authoritative Git state for local input receipts."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError
from scripts.ci_local_receipt_git_nested import NestedRepositories
from scripts.ci_local_receipt_git_runtime import (
    bootstrap,
    config_entries,
    configuration_digest,
    runner,
)
from scripts.ci_local_receipt_git_tree import capture_tree, require_clean_status
from scripts.rc0_candidate.git_controls import check_layout_controls
from scripts.rc0_candidate.git_inspection import _open_directory
from scripts.rc0_candidate.git_layout import GitLayout, GitLayoutChanged, GitLayoutError
from scripts.rc0_candidate.git_policy import GitInspectionError
from scripts.rc0_policy.canonical import canonical_bytes


def capture_repository_state(root: Path, git: Path) -> dict:
    root_fd = _open_directory(root)
    layout = None
    nested = None
    try:
        layout = GitLayout.capture(
            root_fd, lambda fd, *args, **opts: bootstrap(git, fd, *args, **opts)
        )
        run = runner(git, layout)
        before = configuration_digest(layout)
        check_layout_controls(
            root_fd, layout, run, lambda fd: config_entries(run, fd)
        )
        tree = capture_tree(run, root_fd)
        nested = NestedRepositories.capture(layout, tree.gitlinks, git)
        require_clean_status(run, root_fd)
        after = configuration_digest(layout)
        check_layout_controls(
            root_fd, layout, run, lambda fd: config_entries(run, fd)
        )
        nested_records = nested.finish()
        layout.assert_unchanged()
        if before != after:
            raise LocalInputReceiptError("source Git configuration changed")
        metadata = hashlib.sha256(canonical_bytes({
            "root_git_metadata_sha256": after,
            "root_source_sha256": tree.source_sha256,
            "nested_repositories": nested_records,
        })).hexdigest()
        return {
            "source_revision": tree.head, "source_tree": tree.tree_oid,
            "repository_identity": {
                "worktree_dev": layout.root_state[0],
                "worktree_ino": layout.root_state[1],
                "git_dir_dev": layout.git_state[0],
                "git_dir_ino": layout.git_state[1],
            },
            "git_metadata_sha256": metadata,
        }
    except (GitInspectionError, GitLayoutChanged, GitLayoutError, OSError, UnicodeDecodeError) as error:
        raise LocalInputReceiptError("source identity is unavailable") from error
    finally:
        if nested is not None:
            nested.close()
        if layout is not None:
            layout.close()
        os.close(root_fd)


def repository_location(root: Path, git: Path) -> tuple[Path, dict[str, int]]:
    state = capture_repository_state(root, git)
    root_fd = _open_directory(root)
    layout = None
    try:
        layout = GitLayout.capture(
            root_fd, lambda fd, *args, **opts: bootstrap(git, fd, *args, **opts)
        )
        return layout.git_path, state["repository_identity"]
    finally:
        if layout is not None:
            layout.close()
        os.close(root_fd)
