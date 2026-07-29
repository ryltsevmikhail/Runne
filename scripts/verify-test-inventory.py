#!/usr/bin/env python3
"""Verify that a Rust test inventory contains every required test name."""

import pathlib
import sys
import unittest


TEST_SUFFIX = ": test"


def verify_inventory(output: str, required: list[str]) -> list[str]:
    """Return diagnostics for invalid or incomplete Rust test inventory output."""
    errors: list[str] = []

    if not required:
        errors.append("missing required test names")

    seen_required: set[str] = set()
    for name in required:
        if name in seen_required:
            errors.append(f"duplicate required test name: {name}")
        seen_required.add(name)

    inventory = {
        line[: -len(TEST_SUFFIX)]
        for line in output.splitlines()
        if line.endswith(TEST_SUFFIX)
    }
    if not inventory:
        errors.append("missing Rust test inventory entries")

    for name in required:
        if name not in inventory:
            errors.append(f"missing required test: {name}")

    return errors


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        print("missing test inventory path", file=sys.stderr)
        return 1

    inventory_path = pathlib.Path(arguments[0])
    try:
        output = inventory_path.read_text()
    except OSError as error:
        print(f"unable to read test inventory: {error}", file=sys.stderr)
        return 1

    errors = verify_inventory(output, arguments[1:])
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
