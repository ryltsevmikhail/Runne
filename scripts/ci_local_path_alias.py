"""Narrowly recognize root-owned host path aliases used by macOS."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def is_standard_macos_var_alias(absolute: Path, canonical: Path) -> bool:
    if sys.platform != "darwin" or not absolute.is_relative_to("/var"):
        return False
    expected = Path("/private/var").joinpath(*absolute.parts[2:])
    try:
        alias = os.lstat("/var")
        target = os.readlink("/var")
    except OSError:
        return False
    return (
        canonical == expected
        and stat.S_ISLNK(alias.st_mode)
        and alias.st_uid == 0
        and target == "private/var"
    )
