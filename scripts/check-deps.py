#!/usr/bin/env python3
"""Verify gocode workspace dependency boundaries."""
import json
import subprocess
import sys


POLICIES = {
    "gocode-domain": {"uuid", "sha2", "hex", "chrono", "serde"},
    "gocode-plugin-protocol": set(),
    "gocode-observability": {"gocode-application"},
    "gocode-platform": {"gocode-application", "libc", "thiserror", "uuid"},
}


def main() -> int:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    metadata = json.loads(result.stdout)

    found: set[str] = set()
    errors: list[str] = []

    for pkg in metadata["packages"]:
        name = pkg["name"]
        if name not in POLICIES:
            continue
        found.add(name)

        deps = pkg.get("dependencies", [])
        production_deps = {
            dep["name"]
            for dep in deps
            if dep.get("kind") != "dev"
        }
        disallowed = production_deps - POLICIES[name]
        if disallowed:
            errors.append(
                f"FAIL: {name} has disallowed production dependencies: "
                f"{sorted(disallowed)}"
            )

    missing = set(POLICIES) - found
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

    print(
        f"OK: {len(found)}/{len(POLICIES)} workspace packages satisfy dependency policies"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
