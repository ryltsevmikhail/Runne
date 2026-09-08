#!/usr/bin/env python3
"""Backend inventory verifier (Plan Task 1).

Validates that the Phase 1 backend profile and the workspace Cargo.lock
agree exactly: every lock crate is pinned in the profile with matching
version + checksum, every pinned crate carries a license, the recorded
native feature graph is present in Cargo metadata, and the vendored llama.cpp
tree digest matches recomputation from its resolved Cargo package. An explicit
--native-dir must resolve to that same package source.

Usage:
  python3 verify_backend_inventory.py --profile PROFILE.json \
      --lock Cargo.lock [--native-dir DIR]

Exit 0 = inventory consistent; exit 1 = rejection (reason on stderr).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

DIGEST_METHOD = "sha256-of-sorted-file-digests-v1"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"


class Rejection(Exception):
    pass


def reject(reason: str) -> None:
    raise Rejection(reason)


def compute_tree_digest(root: Path) -> str:
    lines = []
    for dirpath, dirnames, filenames in root.walk():
        symlinked_dirs = [name for name in dirnames if (dirpath / name).is_symlink()]
        if symlinked_dirs:
            reject(f"native tree contains symlinked directory: {symlinked_dirs[0]}")
        dirnames.sort()
        for fn in sorted(filenames):
            p = dirpath / fn
            if p.is_symlink() or not p.is_file():
                reject(f"native tree contains non-regular file: {p.relative_to(root)}")
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            lines.append(f"{h}  {p.relative_to(root).as_posix()}")
    blob = "\n".join(sorted(lines)) + "\n"
    return hashlib.sha256(blob.encode()).hexdigest()


def profile_pins(profile: dict) -> dict[tuple[str, str], dict]:
    # Cargo allows multiple versions of one crate in a lock; match on
    # (name, version) pairs, not names.
    pinned = {}
    for entry in profile.get("crates", []):
        try:
            key = (entry["name"], entry["version"])
        except (KeyError, TypeError):
            reject("profile pin missing name or version")
        if key in pinned:
            reject(f"duplicate profile pin: {key[0]} {key[1]}")
        pinned[key] = entry
    if not pinned:
        reject("profile declares no pinned crates")
    return pinned


def check_lock_against_profile(profile: dict, lock_path: Path) -> tuple[int, dict[tuple[str, str], dict]]:
    pinned = profile_pins(profile)
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package", [])
    matched = 0
    matched_pins = set()
    for pkg in packages:
        name = pkg["name"]
        source = pkg.get("source")
        checksum = pkg.get("checksum")
        if source is None:
            if checksum:
                reject(f"local crate unexpectedly has registry checksum: {name} {pkg['version']}")
            # Local workspace members are first-party and have no registry pin.
            continue
        if source != CRATES_IO_SOURCE:
            reject(f"non-registry source in lock: {name} {pkg['version']}")
        if not checksum:
            reject(f"registry crate missing checksum: {name} {pkg['version']}")
        key = (name, pkg["version"])
        if key not in pinned:
            reject(f"unpinned crate in lock: {name} {pkg['version']}")
        entry = pinned[key]
        if pkg.get("checksum") != entry["checksum"]:
            reject(f"checksum mismatch for {name} {pkg['version']}: changed upstream pin")
        matched += 1
        matched_pins.add(key)
    if matched == 0:
        reject("no registry lock crates matched profile pins")
    for name, version in sorted(set(pinned) - matched_pins):
        reject(f"profile pin absent from lock: {name} {version}")
    return matched, pinned


def load_cargo_metadata(lock_path: Path) -> dict:
    manifest_path = lock_path.parent / "Cargo.toml"
    if not manifest_path.is_file():
        reject(f"workspace manifest not found beside lock: {manifest_path}")
    cargo = os.environ.get("CARGO", "cargo")
    try:
        result = subprocess.run(
            [
                cargo,
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--features",
                "runne-llama-worker/backend-llama-cpp",
                "--manifest-path",
                str(manifest_path),
            ],
            cwd=manifest_path.parent,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        reject(f"cannot execute cargo metadata: {exc}")
    if result.returncode:
        reject("cargo metadata failed for locked workspace")
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        reject(f"cargo metadata produced invalid JSON: {exc}")
    if not isinstance(metadata.get("packages"), list) or not isinstance(metadata.get("resolve"), dict):
        reject("cargo metadata missing packages or resolve graph")
    return metadata


def resolved_package(metadata: dict, crate_name: str, pinned: dict[tuple[str, str], dict]) -> dict:
    versions = {version for name, version in pinned if name == crate_name}
    if not versions:
        reject(f"profile feature/native crate is not pinned: {crate_name}")
    matches = [
        package
        for package in metadata["packages"]
        if package.get("name") == crate_name and package.get("version") in versions
    ]
    if len(matches) != 1:
        reject(f"cargo metadata has no unique resolved package for {crate_name}")
    package = matches[0]
    package_id = package.get("id")
    if not isinstance(package_id, str):
        reject(f"cargo metadata package has no id: {crate_name}")
    nodes = [node for node in metadata["resolve"].get("nodes", []) if node.get("id") == package_id]
    if len(nodes) != 1:
        reject(f"cargo metadata has no unique resolved node for {crate_name}")
    package["_resolved_features"] = nodes[0].get("features", [])
    return package


def resolved_native_package(metadata: dict, directory_name: str, pinned: dict[tuple[str, str], dict]) -> dict:
    matches = [
        package
        for package in metadata["packages"]
        if (package.get("name"), package.get("version")) in pinned
        and Path(package.get("manifest_path", "")).parent.name == directory_name
    ]
    if len(matches) != 1:
        reject(f"cargo metadata has no unique native package directory: {directory_name}")
    package = matches[0]
    nodes = [node for node in metadata["resolve"].get("nodes", []) if node.get("id") == package.get("id")]
    if len(nodes) != 1:
        reject(f"cargo metadata has no unique resolved node for native package: {directory_name}")
    return package


def check_features(profile: dict, metadata: dict, pinned: dict[tuple[str, str], dict]) -> None:
    metadata_licenses = {(p.get("name"), p.get("version")): p.get("license") for p in metadata["packages"]}
    for (crate, version), entry in pinned.items():
        license_id = entry.get("license")
        if not isinstance(license_id, str) or not license_id.strip() or license_id.lower() == "true":
            reject(f"missing or placeholder license for pinned crate {crate} {version}")
        if metadata_licenses.get((crate, version)) != license_id:
            reject(f"license mismatch with Cargo metadata for {crate} {version}")
    for crate, spec in profile.get("features", {}).items():
        if not isinstance(spec, dict):
            reject(f"malformed feature profile for {crate}")
        allowed = set(spec.get("allowed", []))
        recorded = spec.get("recorded", [])
        if not isinstance(recorded, list):
            reject(f"malformed recorded feature list for {crate}")
        package = resolved_package(metadata, crate, pinned)
        declared = set(package.get("features", {}))
        active = set(package["_resolved_features"])
        if active != allowed:
            reject(
                f"active Cargo features do not match allowed set for {crate}: "
                f"active {sorted(active)}, allowed {sorted(allowed)}"
            )
        for feature in recorded:
            if feature not in allowed:
                reject(
                    f"unknown build feature for {crate}: {feature} "
                    f"not in allowed set {sorted(allowed)}"
                )
            if feature not in declared:
                reject(f"recorded feature absent from Cargo manifest for {crate}: {feature}")
            if feature not in active:
                reject(f"recorded feature not active in Cargo metadata for {crate}: {feature}")


def check_native_tree(
    profile: dict,
    native_dir: Path | None,
    metadata: dict,
    pinned: dict[tuple[str, str], dict],
) -> None:
    native = profile.get("native", {})
    if not isinstance(native, dict):
        reject("malformed native profile")
    if native.get("digest_method") != DIGEST_METHOD:
        reject(f"unsupported digest method: {native.get('digest_method')}")
    digest = native.get("tree_digest", "")
    if len(digest) != 64:
        reject("native tree_digest missing or malformed")
    vendored_dir = native.get("vendored_dir")
    inside_crate = native.get("inside_crate")
    if not isinstance(vendored_dir, str) or not isinstance(inside_crate, str):
        reject("native profile missing vendored_dir or inside_crate")
    relative_vendored = Path(vendored_dir)
    if relative_vendored.is_absolute() or ".." in relative_vendored.parts:
        reject("native vendored_dir must be a relative descendant")
    package = resolved_native_package(metadata, inside_crate, pinned)
    manifest_path = Path(package.get("manifest_path", ""))
    expected_dir = manifest_path.parent / relative_vendored
    if native_dir is None:
        native_dir = expected_dir
    elif native_dir.resolve() != expected_dir.resolve():
        reject("native dir is not owned by the resolved Cargo package")
    if not native_dir.is_dir():
        reject(f"native dir not found: {native_dir}")
    expected_file_count = native.get("file_count")
    if not isinstance(expected_file_count, int) or isinstance(expected_file_count, bool) or expected_file_count <= 0:
        reject("native file_count missing or malformed")
    actual = compute_tree_digest(native_dir)
    actual_file_count = sum(1 for path in native_dir.rglob("*") if path.is_file() and not path.is_symlink())
    if actual_file_count != expected_file_count:
        reject(
            "native tree file count mismatch: unrecorded or removed embedded source "
            f"(recorded {expected_file_count}, actual {actual_file_count})"
        )
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
        lock_path = Path(args.lock).resolve()
        matched, pinned = check_lock_against_profile(profile, lock_path)
        metadata = load_cargo_metadata(lock_path)
        check_features(profile, metadata, pinned)
        check_native_tree(profile, Path(args.native_dir) if args.native_dir else None, metadata, pinned)
    except Rejection as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        "OK: inventory consistent "
        f"({matched} lock crates checked; features and resolved native digest verified)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
