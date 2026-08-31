"""Argument parsing, JSON loading, canonicalization, and digest checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from typing import Any

from .constants import BASE, errors


def display_path(path: str) -> str:
    """Prefer a repository-relative path, falling back across Windows drives."""
    try:
        return os.path.relpath(path, BASE)
    except ValueError:
        return os.path.abspath(path)


def load_json(path: str) -> Any:
    """Load repository artifacts as UTF-8 regardless of the host locale."""
    with open(path, encoding="utf-8") as json_file:
        return json.load(json_file)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify GOCODE migration evidence artifacts."
    )
    parser.add_argument(
        "--golden-dir",
        default=os.path.join(BASE, "docs", "golden", "migration"),
        help="directory containing migration JSON fixtures (default: %(default)s)",
    )
    parser.add_argument(
        "--schema",
        default=os.path.join(BASE, "docs", "schemas", "migration-evidence-v1.schema.json"),
        help="migration evidence JSON Schema path (default: %(default)s)",
    )
    return parser.parse_args(argv)


def jcs_canonicalize(obj: Any) -> bytes:
    """Serialize a JSON value in canonical form (sorted keys, no whitespace, UTF-8)."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_digest(obj: Any) -> str:
    """Compute sha256:<hex> of JCS-canonicalized bytes."""
    return "sha256:" + hashlib.sha256(jcs_canonicalize(obj)).hexdigest()


def verify_digest_sidecar(json_path: str, instance: Any) -> None:
    """Compare JCS-canonical digest against the .digest sidecar."""
    digest_path = json_path + ".digest"
    if not os.path.exists(digest_path):
        errors.append(f"{display_path(json_path)}: missing .digest sidecar")
        return

    with open(digest_path, encoding="utf-8") as digest_file:
        expected = digest_file.read().strip()
    actual = compute_digest(instance)

    if actual != expected:
        errors.append(
            f"{display_path(json_path)}: digest mismatch - "
            f"expected {expected}, computed {actual}"
        )
    else:
        print(f"  OK digest matches: {actual}")
