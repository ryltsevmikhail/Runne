#!/usr/bin/python3 -I
"""Emit a deterministic digest manifest for installing this reference package."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INSTALL_FILES = frozenset({
    "README.md", "com.gocode.sourcecraft-native-qualification-signer.plist", "codec.py", "contract.py", "controller.py", "ed25519_verify.py",
    "controller_entry.py", "installation_manifest.py", "native_checks.py", "package_subject.py", "policy.py", "process_control.py", "signer.py", "signer_broker.py", "signer_broker_entry.py", "signer_entry.py", "signer_request.py", "signer_request_entry.py", "vector_harness.py", "vector_harness_entry.py", "verifier.py", "verifier_entry.py",
})
DESTINATIONS = {"com.gocode.sourcecraft-native-qualification-signer.plist":"/Library/LaunchDaemons/com.gocode.sourcecraft-native-qualification-signer.plist"}
ENTRYPOINTS = {"controller_entry.py":"sourcecraft-native-qualification-controller", "verifier_entry.py":"sourcecraft-native-qualification-verifier", "vector_harness_entry.py":"sourcecraft-native-qualification-vector-harness", "signer_entry.py":"sourcecraft-native-qualification-sign-evidence", "signer_broker_entry.py":"sourcecraft-native-qualification-signer-broker", "signer_request_entry.py":"sourcecraft-native-qualification-request-signature"}


def main() -> int:
    if set(path.name for path in ROOT.iterdir() if path.is_file()) - INSTALL_FILES:
        raise SystemExit("unaccounted installation source file")
    files = []
    for name in sorted(INSTALL_FILES):
        path = ROOT / name
        if not path.is_file() or path.is_symlink(): raise SystemExit("installation source is absent")
        executable = name in ENTRYPOINTS
        destination = ENTRYPOINTS.get(name, DESTINATIONS.get(name, name))
        files.append({"destination": destination if destination.startswith("/") else f"/opt/gocode/sourcecraft/bin/{destination}",
                      "executable": executable, "group": 0,
                      "mode": "0555" if executable else "0444", "owner": 0,
                      "path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    print(json.dumps({"schema_version": "runne/sourcecraft-native-qualification-install/v1",
                      "files": files}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
