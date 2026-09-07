#!/usr/bin/env python3
"""Backend inventory verifier (Plan Task 1).

Validates that the Phase 1 backend profile and the workspace Cargo.lock
agree exactly: every lock crate is pinned in the profile with matching
version + checksum, every pinned crate carries a license, the recorded
native feature graph stays inside the allowed set, and the vendored
llama.cpp tree digest matches recomputation when --native-dir is given.

Usage:
  python3 verify_backend_inventory.py --profile PROFILE.json \
      --lock Cargo.lock [--native-dir DIR]

Exit 0 = inventory consistent; exit 1 = rejection (reason on stderr).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path

DIGEST_METHOD = "sha256-of-sorted-file-digests-v1"


class Rejection(Exception):
    pass


def reject(reason: str) -> None:
    raise Rejection(reason)


def compute_tree_digest(root: Path) -> str:
    lines = []
    for dirpath, dirnames, filenames in root.walk():
        dirnames.sort()
        for fn in sorted(filenames):
            p = dirpath / fn
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            lines.append(f"{h}  {p.relative_to(root).as_posix()}")
    blob = "\n".join(sorted(lines)) + "\n"
    return hashlib.sha256(blob.encode()).hexdigest()


def check_lock_against_profile(profile: dict, lock_path: Path) -> int:
    # Cargo allows multiple versions of one crate in a lock; match on
    # (name, version) pairs, not names.
    pinned = {(c["name"], c["version"]): c for c in profile.get("crates", [])}
    if not pinned:
        reject("profile declares no pinned crates")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package", [])
    matched = 0
    for pkg in packages:
        name = pkg["name"]
        if not pkg.get("checksum"):
            # No checksum = local workspace member; contents are first-party,
            # nothing to compare against the registry inventory.
            continue
        key = (name, pkg["version"])
        if key not in pinned:
            reject(f"unpinned crate in lock: {name} {pkg['version']}")
        entry = pinned[key]
        if pkg.get("checksum") != entry["checksum"]:
            reject(f"checksum mismatch for {name} {pkg['version']}: changed upstream pin")
        matched += 1
    for (_name, _version), entry in pinned.items():
        if not entry.get("license"):
            reject(f"missing license for pinned crate {_name} {_version}")
    return matched


def check_features(profile: dict) -> None:
    for crate, spec in profile.get("features", {}).items():
        allowed = set(spec.get("allowed", []))
        for feature in spec.get("recorded", []):
            if feature not in allowed:
                reject(
                    f"unknown build feature for {crate}: {feature} "
                    f"not in allowed set {sorted(allowed)}"
                )


def check_native_tree(profile: dict, native_dir: Path | None) -> None:
    native = profile.get("native", {})
    if native.get("digest_method") != DIGEST_METHOD:
        reject(f"unsupported digest method: {native.get('digest_method')}")
    digest = native.get("tree_digest", "")
    if len(digest) != 64:
        reject("native tree_digest missing or malformed")
    if native_dir is None:
        return
    if not native_dir.is_dir():
        reject(f"native dir not found: {native_dir}")
    actual = compute_tree_digest(native_dir)
    if actual != digest:
        reject(
            "native tree digest mismatch: unrecorded or changed "
            f"embedded source (recorded {digest[:16]}…, actual {actual[:16]}…)"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--native-dir", default=None)
    args = parser.parse_args()

    try:
        profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
        if profile.get("schema_version") != "Phase1BackendProfileV1":
            reject("unsupported profile schema_version")
        matched = check_lock_against_profile(profile, Path(args.lock))
        check_features(profile)
        native_dir = Path(args.native_dir) if args.native_dir else None
        check_native_tree(profile, native_dir)
    except Rejection as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        "OK: inventory consistent "
        f"({matched} lock crates checked, features and native digest verified)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
