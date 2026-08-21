"""Checked-in provenance policy for the embedded OpenCode upstream tree."""

from __future__ import annotations

import hashlib

PINNED_OPENCODE_SOURCE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
PINNED_UPSTREAM_TREE_OID = "9c6a3c67c1391b9b8442df34d7735a90f115522c"
PINNED_UPSTREAM_BLOBS: tuple[tuple[bytes, str], ...] = (
    (
        b"opencode/packages/sdk/openapi.json",
        "063e1cc745665f3846be7911e1eb793dcfe45bca5ae3cc425ab246b80eeec4ce",
    ),
)


def pinned_upstream_blob_count() -> int:
    return len(PINNED_UPSTREAM_BLOBS)


def pinned_upstream_content_digest() -> str:
    digest = hashlib.sha256()
    for path, blob_sha256 in PINNED_UPSTREAM_BLOBS:
        digest.update(path)
        digest.update(bytes.fromhex(blob_sha256))
    return digest.hexdigest()
