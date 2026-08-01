import pathlib
import re

from .io import digest, exact_fields, safe_path, valid_hex

def validate_artifacts_and_profiles(
    source_root, manifest, candidate_root, candidate_file, block
):
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("missing artifacts")
    artifact_digests = set()
    artifact_paths = set()
    for artifact in artifacts:
        if not exact_fields(artifact, ("path", "target", "sha256", "kind")) or not safe_path(artifact["path"]) or artifact["path"] in artifact_paths or not valid_hex(artifact["sha256"]):
            raise ValueError("invalid artifact")
        artifact_paths.add(artifact["path"])
        if digest(candidate_file(artifact["path"])) != artifact["sha256"]:
            block("artifact-digest")
        artifact_digests.add(artifact["sha256"])

    profiles = manifest["profiles"]
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("missing profiles")
    profile_digests = []
    profile_bindings = []
    for profile in profiles:
        if not exact_fields(profile, ("name", "revision", "path", "sha256")) or not isinstance(profile["name"], str) or not profile["name"].strip() or not isinstance(profile["revision"], int) or isinstance(profile["revision"], bool) or not safe_path(profile["path"]) or not valid_hex(profile["sha256"]):
            raise ValueError("invalid profile")
        profile_path = candidate_file(profile["path"])
        if digest(profile_path) != profile["sha256"]:
            block("profile-integrity")
        source_profile = source_root / "docs" / "profiles" / pathlib.PurePosixPath(profile["path"]).name
        sidecar = source_profile.with_suffix(".digest")
        if not source_profile.is_file() or not sidecar.is_file() or sidecar.read_text(encoding="utf-8").strip() != f"sha256:{digest(source_profile)}" or digest(source_profile) != profile["sha256"]:
            block("profile-integrity")
        profile_digests.append(profile["sha256"])
        profile_bindings.append({"name": profile["name"], "revision": profile["revision"], "sha256": profile["sha256"]})
    if len(set(profile_digests)) != len(profile_digests):
        raise ValueError("duplicate profile digest")

    checksum_path = candidate_root / "checksums.sha256"
    checksums = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines(keepends=True):
        if not re.fullmatch(r"[0-9a-f]{64}  [^\n]+\n", line):
            raise ValueError("malformed checksum")
        item_digest, relative = line[:-1].split("  ", 1)
        if not safe_path(relative) or relative in checksums:
            raise ValueError("unsafe or duplicate checksum path")
        checksums[relative] = item_digest
    if list(checksums) != sorted(checksums, key=lambda item: item.encode("utf-8")):
        raise ValueError("unsorted checksums")
    actual_files = {path.relative_to(candidate_root).as_posix() for path in candidate_root.rglob("*") if path.is_file() and path.name not in {"checksums.sha256", "release-manifest.v1.json"}}
    if set(checksums) != actual_files:
        raise ValueError("unbound candidate file")
    for relative, expected in checksums.items():
        if digest(candidate_file(relative)) != expected:
            block("checksums")
    return artifacts, artifact_digests, profile_digests, profile_bindings
