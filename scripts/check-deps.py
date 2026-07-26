#!/usr/bin/env python3
"""Verify gocode workspace dependency boundaries."""
import json
import subprocess
import sys


REQUIRED_PACKAGES = {"gocode-domain", "gocode-plugin-protocol"}


def main() -> int:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        capture_output=True, text=True, check=True,
    )
    metadata = json.loads(result.stdout)

    found: set[str] = set()
    errors: list[str] = []

    for pkg in metadata["packages"]:
        name = pkg["name"]
        if name not in REQUIRED_PACKAGES:
            continue
        found.add(name)

        deps = pkg.get("dependencies", [])
        if deps:
            dep_names = [d["name"] for d in deps]
            errors.append(f"FAIL: {name} has dependencies: {dep_names}")

    missing = REQUIRED_PACKAGES - found
    if missing:
        errors.append(f"FAIL: workspace packages not found: {missing}")

    # Check protocol does not depend on domain
    for pkg in metadata["packages"]:
        if pkg["name"] != "gocode-plugin-protocol":
            continue
        for dep in pkg.get("dependencies", []):
            if dep["name"] == "gocode-domain":
                errors.append("FAIL: gocode-plugin-protocol depends on gocode-domain")

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    print(f"OK: {len(found)}/{len(REQUIRED_PACKAGES)} workspace packages, zero dependencies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
