#!/usr/bin/env python3
"""Audit repository source files against a physical line-count limit."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Iterable


SOURCE_SUFFIXES = frozenset(
    {
        ".cjs",
        ".css",
        ".html",
        ".inc",
        ".js",
        ".jsx",
        ".mjs",
        ".py",
        ".rs",
        ".scss",
        ".sh",
        ".sql",
        ".ts",
        ".tsx",
        ".vue",
    }
)
DEFAULT_EXCLUDES = (
    "upstream/",
    ".worktrees/",
    "node_modules/",
    "target/",
    "dist/",
    "build/",
    "apps/desktop/src-tauri/gen/",
)


@dataclass(frozen=True)
class FileLength:
    path: str
    lines: int


def is_excluded(path: str, patterns: Iterable[str]) -> bool:
    """Return whether a repository-relative path matches an exclusion."""
    return any(
        path.startswith(pattern) or fnmatch(path, pattern) for pattern in patterns
    )


def is_source_path(path: str) -> bool:
    """Return whether a repository-relative path is in the source scope."""
    return pathlib.PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES


def count_text_lines(path: pathlib.Path) -> int | None:
    """Count physical text lines, returning None for binary files."""
    data = path.read_bytes()
    if b"\0" in data:
        return None
    return data.count(b"\n") + int(bool(data) and not data.endswith(b"\n"))


def audit_paths(
    root: pathlib.Path,
    paths: Iterable[str],
    max_lines: int,
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
) -> tuple[list[FileLength], list[FileLength]]:
    """Return checked files and files exceeding ``max_lines`` in stable order."""
    checked: list[FileLength] = []
    violations: list[FileLength] = []
    exclusion_patterns = tuple(excludes)

    for relative in sorted(paths):
        if is_excluded(relative, exclusion_patterns) or not is_source_path(relative):
            continue
        file_path = root / relative
        if not file_path.is_file():
            # ``git ls-files --cached`` includes tracked files deleted in the
            # working tree. Deleted source files are no longer part of the
            # checked source surface.
            continue
        try:
            lines = count_text_lines(file_path)
        except OSError as error:
            raise RuntimeError(f"unable to read {relative}: {error}") from error
        if lines is None:
            continue
        result = FileLength(relative, lines)
        checked.append(result)
        if lines > max_lines:
            violations.append(result)

    violations.sort(key=lambda item: (-item.lines, item.path))
    return checked, violations


def repository_root() -> pathlib.Path:
    """Resolve the current Git worktree root."""
    try:
        output = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(f"unable to resolve Git worktree root: {error}") from error
    return pathlib.Path(output.strip()).resolve()


def repository_paths(root: pathlib.Path) -> list[str]:
    """Return tracked and non-ignored worktree paths using Git."""
    try:
        output = subprocess.check_output(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(f"unable to list tracked files: {error}") from error
    return [path.decode("utf-8") for path in output.split(b"\0") if path]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-lines", type=int, required=True)
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="additional repository-relative prefix or glob to exclude",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="report violations without returning a failure status",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    if arguments.max_lines < 0:
        print("--max-lines must be non-negative", file=sys.stderr)
        return 2

    try:
        root = repository_root()
        checked, violations = audit_paths(
            root,
            repository_paths(root),
            arguments.max_lines,
            (*DEFAULT_EXCLUDES, *arguments.exclude),
        )
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    print(f"Source file-length audit (max={arguments.max_lines})")
    print(f"Checked: {len(checked)}")
    print(f"Passing: {len(checked) - len(violations)}")
    print(f"Violations: {len(violations)}")
    for violation in violations:
        print(f"OVER {violation.lines:5d} {violation.path}")

    if violations and not arguments.report:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
