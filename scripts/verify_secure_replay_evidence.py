#!/usr/bin/env python3
"""Verify immutable Secure Replay evidence records from Git objects."""

from __future__ import annotations

import argparse
import pathlib

from secure_replay_evidence_verifier import fail, verify_legacy, verify_v2


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=pathlib.Path)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--schema", type=pathlib.Path)
    parser.add_argument("--legacy-blob")
    arguments = parser.parse_args()
    if arguments.legacy_blob:
        if any((arguments.base, arguments.head, arguments.schema)):
            fail("legacy verification accepts only --manifest and --legacy-blob")
        verify_legacy(arguments.manifest, arguments.legacy_blob)
    elif arguments.base and arguments.head and arguments.schema:
        verify_v2(arguments.manifest, arguments.base, arguments.head, arguments.schema)
    else:
        fail("v2 verification requires --manifest, --base, --head and --schema")
    print("secure replay evidence manifest verified")


if __name__ == "__main__":
    main()
