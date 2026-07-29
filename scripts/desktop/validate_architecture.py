#!/usr/bin/env python3
"""Validate repository dependency boundaries."""

import json
from pathlib import Path
import subprocess
import sys


ALLOWED_RUST_DEPENDENCIES: dict[str, set[str]] = {
    "gocode-desktop": {"gocode-app-core", "gocode-platform-desktop"},
    "gocode-app-core": {
        "gocode-local-store",
        "gocode-platform-ports",
        "gocode-runtime-client",
        "gocode-secure-store",
    },
    "gocode-platform-desktop": {"gocode-platform-ports"},
    "gocode-platform-mobile": {"gocode-platform-ports"},
    "gocode-local-store": {"gocode-secure-store"},
    "gocode-platform-ports": set(),
    "gocode-pairing-crypto": set(),
    "gocode-runtime-client": set(),
    "gocode-secure-store": set(),
}


def find_rust_dependency_violations(
    dependencies: dict[str, set[str]],
) -> list[str]:
    violations: list[str] = []
    for package, package_dependencies in sorted(dependencies.items()):
        allowed = ALLOWED_RUST_DEPENDENCIES.get(package, set())
        for dependency in sorted(package_dependencies):
            if dependency.startswith("gocode-") and dependency not in allowed:
                violations.append(f"{package} -> {dependency} is forbidden")
    return violations


def load_workspace_dependencies(root: Path) -> dict[str, set[str]]:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    return {
        package["name"]: {
            dependency["name"]
            for dependency in package["dependencies"]
            if dependency["name"].startswith("gocode-")
        }
        for package in metadata["packages"]
        if package["name"] in ALLOWED_RUST_DEPENDENCIES
    }


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    violations = find_rust_dependency_violations(load_workspace_dependencies(root))
    if violations:
        for violation in violations:
            print(f"ERROR: {violation}")
        return 1
    print("Rust dependency boundaries passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
