"""Trusted host path resolution for the local CI namespace."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from scripts.ci_local_path_alias import is_standard_macos_var_alias
from scripts.ci_local_receipt_common import LocalInputReceiptError


def _private_tmpdir(path: Path) -> Path:
    try:
        absolute = path.absolute()
        canonical = path.resolve(strict=True)
        metadata = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        raise LocalInputReceiptError("TMPDIR is unavailable") from error
    if (
        (absolute != canonical and not is_standard_macos_var_alias(absolute, canonical))
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise LocalInputReceiptError("TMPDIR is not owner-private mode 0700")
    return canonical
