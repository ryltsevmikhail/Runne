"""Validation of atomically completed private evidence namespaces."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .publish_completion import CompletionPublishError, assert_completed_bound
from .publish_fs import (
    DIRECTORY, OWNER_XATTR, PublishFilesystemError, assert_lock_bound, entry_state,
    open_existing_lock, open_root, read_regular,
)
from .publish_recovery import RecoveryError

_SHA = re.compile(r"[0-9a-f]{40}")


class CompletionValidationError(ValueError):
    pass


def load_completed_private_blobs(
    output_root: Path,
    source_sha: str,
    expected_names: Sequence[str],
    validation_hook: Callable[[str, int, str], None] | None = None,
    blob_validator: Callable[[Mapping[str, bytes]], None] | None = None,
) -> Mapping[str, bytes]:
    if _SHA.fullmatch(source_sha) is None:
        raise CompletionValidationError("completed evidence source SHA is invalid")
    try:
        root = open_root(Path(output_root), None)
    except PublishFilesystemError as error:
        raise CompletionValidationError(str(error)) from error
    lock_fd = directory_fd = -1
    try:
        lock_name = f".{source_sha}.construction-lock"
        lock_fd, lock_state, owner_id = open_existing_lock(root, lock_name)
        directory_fd = os.open(source_sha, DIRECTORY, dir_fd=root.root_fd)
        metadata = os.fstat(directory_fd)
        directory_state = entry_state(metadata)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
        ):
            raise CompletionValidationError("completed evidence directory mode is unsafe")
        if os.getxattr(directory_fd, OWNER_XATTR) != owner_id:
            raise CompletionValidationError("completed evidence owner identity is invalid")
        if set(os.listdir(directory_fd)) != set(expected_names):
            raise CompletionValidationError("completed evidence does not contain exact blobs")
        blobs = {name: read_regular(directory_fd, name)[0] for name in expected_names}
        assert_completed_bound(
            root, directory_fd, directory_state, source_sha, blobs, owner_id,
            blob_validator,
        )
        if validation_hook is not None:
            validation_hook("before-return", root.root_fd, source_sha)
        assert_lock_bound(root, lock_name, lock_fd, lock_state, owner_id)
        assert_completed_bound(
            root, directory_fd, directory_state, source_sha, blobs, owner_id,
            blob_validator,
        )
        assert_lock_bound(root, lock_name, lock_fd, lock_state, owner_id)
        assert_completed_bound(
            root, directory_fd, directory_state, source_sha, blobs, owner_id,
            blob_validator,
        )
        return dict(blobs)
    except CompletionValidationError:
        raise
    except (
        OSError, CompletionPublishError, PublishFilesystemError, RecoveryError, ValueError,
    ) as error:
        raise CompletionValidationError("completed evidence namespace is unavailable") from error
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        if lock_fd >= 0:
            os.close(lock_fd)
        root.close()
