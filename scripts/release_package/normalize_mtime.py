#!/usr/bin/env python3
"""Apply SOURCE_DATE_EPOCH to every staged candidate entry."""

import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
timestamp = int(sys.argv[2])


def set_mtime(path: pathlib.Path) -> None:
    try:
        os.utime(path, (timestamp, timestamp), follow_symlinks=False)
    except NotImplementedError:
        os.utime(path, (timestamp, timestamp))


for path in sorted(root.rglob("*"), key=lambda item: str(item).encode("utf-8"), reverse=True):
    set_mtime(path)
set_mtime(root)
