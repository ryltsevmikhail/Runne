"""Single-descriptor snapshot for local fixture evidence commits."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .git_controls import check_layout_controls
from .git_inspection import GitInspectionError, _config, _open_directory, _read_retained, _run, _state
from .git_layout import GitLayout, GitLayoutChanged, GitLayoutError

_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_SHA = re.compile(rb"[0-9a-f]{40}")


@dataclass(frozen=True)
class EvidenceCommitSnapshot:
    head: str
    parents: tuple[str, ...]
    status: bytes
    changes: bytes
    tree_results: Mapping[bytes, tuple[bytes, bytes | None]]


def _live(root_fd: int, evidence_revision: str) -> tuple[str, tuple[str, ...], bytes]:
    head = _run(root_fd, "rev-parse", "HEAD").decode("ascii").strip()
    parents = tuple(
        _run(root_fd, "show", "-s", "--format=%P", evidence_revision).decode("ascii").split()
    )
    status = _run(
        root_fd, "status", "--porcelain=v1", "-z", "--untracked-files=all",
        "--ignore-submodules=none",
    )
    return head, parents, status


def _tree_result(root_fd: int, revision: str, raw_path: bytes) -> tuple[bytes, bytes | None]:
    path = raw_path.decode("utf-8")
    tree = _run(root_fd, "ls-tree", "-z", revision, "--", path)
    metadata, separator, listed = tree.removesuffix(b"\0").partition(b"\t")
    fields = metadata.split(b" ")
    if separator != b"\t" or listed != raw_path or len(fields) != 3 or not _SHA.fullmatch(fields[2]):
        return tree, None
    return tree, _run(root_fd, "cat-file", "blob", fields[2].decode("ascii"))


def capture_evidence_commit_snapshot(
    repository: Path,
    source_sha: str,
    evidence_revision: str,
    mutation_hook: Callable[[str, Path], None] | None = None,
) -> EvidenceCommitSnapshot:
    root_fd = _open_directory(Path(repository))
    layout: GitLayout | None = None
    config_fd = -1
    try:
        layout = GitLayout.capture(root_fd, _run)
        config_fd = os.open("config", _FILE, dir_fd=layout.common_fd)
        config_state = _state(os.fstat(config_fd))
        config_bytes = _read_retained(config_fd)
        check_layout_controls(root_fd, layout, _run, _config)
        initial = _live(root_fd, evidence_revision)
        changes = _run(
            root_fd, "diff-tree", "--no-commit-id", "--name-status", "-r",
            "--no-renames", "-z", source_sha, evidence_revision,
        )
        fields = changes.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        results: dict[bytes, tuple[bytes, bytes | None]] = {}
        if len(fields) % 2 == 0:
            for index in range(0, len(fields), 2):
                results[fields[index + 1]] = _tree_result(
                    root_fd, evidence_revision, fields[index + 1]
                )
        if mutation_hook is not None:
            mutation_hook("before-final-recheck", Path(repository))
        check_layout_controls(root_fd, layout, _run, _config)
        final = _live(root_fd, evidence_revision)
        layout.assert_unchanged()
        current_config = os.stat("config", dir_fd=layout.common_fd, follow_symlinks=False)
        if (
            initial != final
            or config_bytes != _read_retained(config_fd)
            or config_state != _state(os.fstat(config_fd))
            or config_state != _state(current_config)
        ):
            raise GitLayoutChanged("evidence Git snapshot changed")
        return EvidenceCommitSnapshot(initial[0], initial[1], initial[2], changes, results)
    except GitLayoutChanged as error:
        raise GitInspectionError("SOURCE_SNAPSHOT_CHANGED", "evidence Git snapshot changed") from error
    except GitInspectionError:
        raise
    except (GitLayoutError, OSError, UnicodeDecodeError, ValueError) as error:
        raise GitInspectionError(
            "SOURCE_GIT_INSPECTION_FAILED", "stable evidence Git snapshot is unavailable"
        ) from error
    finally:
        if config_fd >= 0:
            os.close(config_fd)
        if layout is not None:
            layout.close()
        os.close(root_fd)
