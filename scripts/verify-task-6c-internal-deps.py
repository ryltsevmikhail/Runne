#!/usr/bin/env python3
"""Verify Task 6C's resolved dependency and source-call boundaries."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SENDER = "gocode-daemon-openai-effect"
DAEMON = "gocode-daemon"
FIXTURE = "gocode-daemon-loopback-fixture"
EXPECTED_CONSUMERS = {DAEMON, FIXTURE}
FORBIDDEN = {
    "apps/desktop",
    "crates/app-core",
    "crates/gocode-runtime-client",
    "crates/gocode-api",
}
CALLS = {
    "ProtectedProviderDependencyCapsule::production()": {
        "crates/gocode-daemon/src/main.rs": 2,
        "crates/gocode-daemon/src/application/provider_startup.rs": 2,
        "crates/gocode-daemon/tests/protected_activation_channel.rs": 1,
    },
    "ProtectedProviderDependencyCapsule::from_loopback_fixture(": {
        "crates/gocode-daemon-loopback-fixture/src/protected_process.rs": 1,
    },
    "workspace_internal::start_from_verified_protected_launch(": {
        "crates/gocode-daemon/src/main.rs": 1,
        "crates/gocode-daemon/tests/protected_activation_channel.rs": 1,
        "crates/gocode-daemon-loopback-fixture/src/protected_process.rs": 1,
    },
    "workspace_internal::start_external_from_fixed_source(": {
        "crates/gocode-daemon/src/main.rs": 1,
    },
}


def metadata(*extra: str) -> dict[str, object]:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", *extra],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


def package_map(data: dict[str, object]) -> dict[str, dict[str, object]]:
    return {package["name"]: package for package in data["packages"]}  # type: ignore[index]


def normal_consumers(packages: dict[str, dict[str, object]]) -> set[str]:
    consumers = set()
    for name, package in packages.items():
        for dependency in package["dependencies"]:  # type: ignore[index]
            if dependency["name"] == SENDER and dependency["kind"] is None:
                consumers.add(name)
    return consumers


def dependency_closure(data: dict[str, object], root_name: str) -> set[str]:
    packages = package_map(data)
    ids = {package["id"]: name for name, package in packages.items()}
    nodes = {node["id"]: node for node in data["resolve"]["nodes"]}  # type: ignore[index]
    pending = [packages[root_name]["id"]]
    seen = set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        pending.extend(dependency["pkg"] for dependency in nodes[package_id]["deps"])
    return {ids[package_id] for package_id in seen if package_id in ids}


def check_metadata(label: str, data: dict[str, object]) -> None:
    packages = package_map(data)
    required = {SENDER, DAEMON, FIXTURE}
    if not required.issubset(packages):
        raise SystemExit(f"{label}: required packages are absent from resolved graph")
    unpublished = {name for name in required if packages[name]["publish"] == []}
    if unpublished != required:
        raise SystemExit(f"{label}: Task 6C packages must set publish = false")
    consumers = normal_consumers(packages)
    if consumers != EXPECTED_CONSUMERS:
        raise SystemExit(f"{label}: unexpected normal sender consumers: {sorted(consumers)}")
    if FIXTURE in dependency_closure(data, DAEMON):
        raise SystemExit(f"{label}: daemon resolved closure contains fixture")


def check_targets(data: dict[str, object]) -> None:
    packages = package_map(data)
    owners: dict[str, set[str]] = {}
    for package_name in (DAEMON, FIXTURE):
        for target in packages[package_name]["targets"]:  # type: ignore[index]
            if "bin" in target["kind"]:
                owners.setdefault(target["name"], set()).add(package_name)
    expected = {
        "gocode-daemon": {DAEMON},
        "activation_process": {FIXTURE},
        "recovery_process": {FIXTURE},
    }
    if {name: owners.get(name, set()) for name in expected} != expected:
        raise SystemExit("Task 6C binary targets have unexpected ownership")


def check_forbidden_imports() -> None:
    for relative in FORBIDDEN:
        base = ROOT / relative
        if base.exists() and any(
            SENDER in path.read_text(encoding="utf-8", errors="ignore")
            for path in base.rglob("*.rs")
        ):
            raise SystemExit(f"forbidden sender import: {relative}")


def check_calls() -> None:
    sources = list((ROOT / "crates").rglob("*.rs"))
    for needle, expected in CALLS.items():
        actual = {
            path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8").count(needle)
            for path in sources
            if needle in path.read_text(encoding="utf-8")
        }
        if actual != expected:
            raise SystemExit(f"unexpected call sites for {needle}: {actual}")


def main() -> int:
    default = metadata()
    all_features = metadata("--all-features")
    for label, resolved in (("default", default), ("all-features", all_features)):
        check_metadata(label, resolved)
    check_targets(all_features)
    check_forbidden_imports()
    check_calls()
    print("Task 6C resolved dependency and source-call boundary passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
