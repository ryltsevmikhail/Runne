#!/usr/bin/env python3
"""Validate Cargo JSON artifact messages for the daemon-only release build."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys


DAEMON_PACKAGE = "runne-daemon"
DAEMON_BINARY = "runned"
FIXTURE = "runne-daemon-loopback-fixture"
FORBIDDEN_BINS = {"activation_process", "recovery_process"}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--messages", type=pathlib.Path, required=True)
    parser.add_argument("--target-dir", type=pathlib.Path, required=True)
    return parser.parse_args()


def artifacts(messages: pathlib.Path) -> list[dict[str, object]]:
    result = []
    for line in messages.read_text(encoding="utf-8").splitlines():
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact":
            result.append(message)
    return result


def package_name(artifact: dict[str, object]) -> str:
    source = pathlib.Path(artifact["target"]["src_path"])
    parts = source.parts
    return parts[parts.index("crates") + 1]


def main() -> int:
    args = arguments()
    executable_artifacts = []
    for artifact in artifacts(args.messages):
        target = artifact["target"]
        name = target["name"]
        source = pathlib.Path(target["src_path"])
        if FIXTURE in source.parts or name in FORBIDDEN_BINS:
            raise SystemExit(f"fixture artifact reported by Cargo: {source}/{name}")
        if artifact["executable"] is not None:
            executable_artifacts.append(
                (package_name(artifact), name, pathlib.Path(artifact["executable"]))
            )
    expected = [(DAEMON_PACKAGE, DAEMON_BINARY, args.target_dir / "release" / DAEMON_BINARY)]
    if executable_artifacts != expected:
        raise SystemExit(f"unexpected release executables: {executable_artifacts}")
    executable = expected[0][2]
    if not executable.is_file():
        raise SystemExit(f"daemon executable is missing: {executable}")
    print(f"Task 6C Cargo JSON artifact boundary passed: {executable}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
