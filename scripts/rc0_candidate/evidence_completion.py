"""Validation of atomically completed private evidence namespaces."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .publish_completion import manifest, marker_matches
from .publish_fs import (
    DIRECTORY, OWNER_XATTR, PublishFilesystemError, entry_state, open_root,
    full_state, read_regular,
)

_SHA = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(rb"[0-9a-f]{64}")


class CompletionValidationError(ValueError):
    pass


def load_completed_private_blobs(
    output_root: Path,
    source_sha: str,
    expected_names: Sequence[str],
    validation_hook: Callable[[str, int, str], None] | None = None,
) -> Mapping[str, bytes]:
    if _SHA.fullmatch(source_sha) is None:
        raise CompletionValidationError("completed evidence source SHA is invalid")
    try:
        root = open_root(Path(output_root), None)
    except PublishFilesystemError as error:
        raise CompletionValidationError(str(error)) from error
    directory_fd = -1
    try:
        directory_fd = os.open(source_sha, DIRECTORY, dir_fd=root.root_fd)
        metadata = os.fstat(directory_fd)
        directory_state = entry_state(metadata)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
        ):
            raise CompletionValidationError("completed evidence directory mode is unsafe")
        token = os.getxattr(directory_fd, OWNER_XATTR)
        if _TOKEN.fullmatch(token) is None:
            raise CompletionValidationError("completed evidence owner token is invalid")
        if set(os.listdir(directory_fd)) != set(expected_names):
            raise CompletionValidationError("completed evidence does not contain exact blobs")
        blobs = {name: read_regular(directory_fd, name)[0] for name in expected_names}
        marker_name = f".{source_sha}.complete"
        if not marker_matches(
            root.root_fd, marker_name, source_sha, directory_state, blobs, token
        ):
            raise CompletionValidationError("completion marker binding is invalid")
        directory_path = os.stat(source_sha, dir_fd=root.root_fd, follow_symlinks=False)
        if (
            full_state(metadata) != full_state(os.fstat(directory_fd))
            or full_state(metadata) != full_state(directory_path)
            or set(os.listdir(directory_fd)) != set(expected_names)
            or manifest(source_sha, directory_state, blobs, token)
            != manifest(source_sha, entry_state(directory_path), blobs, token)
        ):
            raise CompletionValidationError("completed evidence namespace changed")
        root.assert_bound()
        if validation_hook is not None:
            validation_hook("before-return", root.root_fd, source_sha)
        root.assert_bound()
        return blobs
    except CompletionValidationError:
        raise
    except (OSError, PublishFilesystemError, ValueError) as error:
        raise CompletionValidationError("completed evidence namespace is unavailable") from error
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        root.close()
