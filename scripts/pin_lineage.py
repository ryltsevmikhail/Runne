#!/usr/bin/env python3
"""Verify explicit evidence-pin successors across Git lineages."""

from __future__ import annotations

import re
import subprocess

_CODE_PATHS = ("crates/", "packages/", "apps/")


def _patch_bytes(commit: str, paths: tuple[str, ...] | None) -> bytes:
    command = ["git", "diff", commit + "^", commit]
    if paths is not None:
        command += list(paths)
    return subprocess.run(command, check=True, capture_output=True).stdout


def require_lineage(evidence: str, field: str) -> str:
    pin = re.search(rf"^{field}: ([0-9a-f]{{40}})$", evidence, re.MULTILINE)
    if pin is None:
        raise SystemExit(f"evidence field is missing: {field}")
    commit = pin.group(1)
    subprocess.run(["git", "cat-file", "-e", commit + "^{commit}"], check=True)
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "HEAD"]
    )
    if ancestor.returncode == 0:
        return commit
    scopes = (("_successor", None, "full"), ("_successor_code", _CODE_PATHS, "code"))
    for suffix, paths, scope in scopes:
        successor = re.search(
            rf"^{field}{suffix}: ([0-9a-f]{{40}})$", evidence, re.MULTILINE
        )
        if successor is None:
            continue
        bound = successor.group(1)
        subprocess.run(["git", "cat-file", "-e", bound + "^{commit}"], check=True)
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", bound, "HEAD"], check=True
        )
        if _patch_bytes(commit, paths) != _patch_bytes(bound, paths):
            raise SystemExit(
                f"{field}{suffix} is not {scope}-patch identical to {field}"
            )
        return bound
    raise SystemExit(f"{field} does not reach HEAD and has no verified successor")
