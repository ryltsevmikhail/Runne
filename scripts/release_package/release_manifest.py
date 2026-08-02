#!/usr/bin/env python3
"""Build the assembled release-manifest.v1 document."""

import hashlib
import json
import pathlib
import sys

candidate_directory = pathlib.Path(sys.argv[1])
version, target, platform, source_revision, lockfile_digest, candidate_digest, binary_name, daemon_digest = sys.argv[2:10]
profile_metadata = json.loads(pathlib.Path(sys.argv[10]).read_text(encoding="utf-8"))

profiles = []
for profile in profile_metadata:
    source = pathlib.Path(profile["source_path"])
    copied_path = f"profiles/{source.name}"
    profiles.append(
        {
            "name": profile["name"],
            "path": copied_path,
            "revision": profile["revision"],
            "sha256": hashlib.sha256((candidate_directory / copied_path).read_bytes()).hexdigest(),
        }
    )
profiles.sort(key=lambda profile: profile["path"].encode("utf-8"))
profile_digests = [profile["sha256"] for profile in profiles]

lanes = []
for lane_id, lane_version in (("pinned-1.97.1", "1.97.1"), ("msrv-1.95.0", "1.95.0")):
    lanes.append(
        {
            "cargo_version": lane_version,
            "hosted_execution_slots": [
                {"platform": slot_platform, "status": "planned"}
                for slot_platform in ("linux", "macos", "windows")
            ],
            "lane_id": lane_id,
            "rustc_version": lane_version,
        }
    )

checksums_path = candidate_directory / "checksums.sha256"
sbom_path = candidate_directory / "sbom.cdx.json"
provenance_path = candidate_directory / "provenance-attestation.json"
artifact_path = binary_name
evidence = []
for gate_id, kind, path, digest in (
    ("package", "package", artifact_path, daemon_digest),
    ("checksums", "checksums", "checksums.sha256", hashlib.sha256(checksums_path.read_bytes()).hexdigest()),
    ("provenance-attestation", "provenance-attestation", "provenance-attestation.json", hashlib.sha256(provenance_path.read_bytes()).hexdigest()),
    ("sbom", "sbom", "sbom.cdx.json", hashlib.sha256(sbom_path.read_bytes()).hexdigest()),
):
    evidence.append(
        {
            "artifact_sha256": daemon_digest,
            "candidate_digest": candidate_digest,
            "gate_id": gate_id,
            "kind": kind,
            "platform": platform,
            "profile_digests": profile_digests,
            "sha256": digest,
            "source_revision": source_revision,
            "uri": f"candidate://{candidate_directory.name}/{path}",
        }
    )

manifest = {
    "artifacts": [
        {"kind": "daemon", "path": artifact_path, "sha256": daemon_digest, "target": target},
        {
            "kind": "license",
            "path": "LICENSES/LICENSE",
            "sha256": hashlib.sha256((candidate_directory / "LICENSES/LICENSE").read_bytes()).hexdigest(),
            "target": target,
        },
        {
            "kind": "sbom",
            "path": "sbom.cdx.json",
            "sha256": hashlib.sha256(sbom_path.read_bytes()).hexdigest(),
            "target": target,
        },
    ],
    "candidate": {
        "lockfile_digest": lockfile_digest,
        "qualification_lanes": lanes,
        "release_version": version,
        "source_revision": source_revision,
    },
    "evidence": evidence,
    "format": "release-manifest.v1",
    "platforms": [
        {
            "artifact_sha256": daemon_digest,
            "os": platform,
            "profile_digests": profile_digests,
            "target": target,
        }
    ],
    "profiles": profiles,
    "qualification_state": "assembled",
}
(candidate_directory / "release-manifest.v1.json").write_bytes(
    json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
