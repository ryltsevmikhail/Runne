"""Blacklist and pinned-source checks for migration fixtures."""

from typing import Any

from .constants import BASELINE_SHA, BLACKLIST_KEYS, errors


def check_blacklist(obj: Any, path: str = "$") -> None:
    """Recursively check for blacklisted keys."""
    if isinstance(obj, dict):
        for key in obj:
            if key.lower() in BLACKLIST_KEYS:
                errors.append(f"{path}: blacklisted key '{key}' found")
            check_blacklist(obj[key], f"{path}.{key}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            check_blacklist(item, f"{path}[{i}]")


def check_source_sha(instance: dict, path: str) -> None:
    """Ensure source_sha matches the pinned baseline."""
    actual = instance.get("source_sha")
    if actual != BASELINE_SHA:
        errors.append(
            f"{path}: source_sha '{actual}' does not match baseline '{BASELINE_SHA}'"
        )
