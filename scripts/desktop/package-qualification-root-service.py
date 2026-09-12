#!/usr/bin/env python3
"""Describe an already signed root-service artifact for a reviewed root install."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

IDENTIFIER = "com.runne.qualification-root-service"
DESTINATION = "/opt/gocode/sourcecraft/bin/runne-qualification-root-service"
LABEL = "com.runne.qualification-runner.root-consume.v1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signed-binary", type=Path, required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Z0-9]{10}", args.team_id):
        parser.error("team id must be ten uppercase alphanumeric characters")
    binary = args.signed_binary
    if binary.is_symlink() or not binary.is_file():
        parser.error("signed binary must be a regular non-symlink file")
    requirement = f'identifier "{IDENTIFIER}" and anchor apple generic and certificate leaf[subject.OU] = "{args.team_id}"'
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "-R", requirement, str(binary)], check=True)
    root = Path(__file__).resolve().parents[2]
    plist = root / "tools/sourcecraft-native-qualification" / f"{LABEL}.plist"
    entries = []
    for source, destination, mode in ((binary, DESTINATION, "0555"),
                                    (plist, f"/Library/LaunchDaemons/{LABEL}.plist", "0444")):
        entries.append({"source": str(source.resolve()), "destination": destination,
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "owner": 0, "group": 0, "mode": mode})
    manifest = {"schema_version": "runne/qualification-root-service-install/v1",
                "identifier": IDENTIFIER, "team_identifier": args.team_id, "files": entries}
    args.output.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
