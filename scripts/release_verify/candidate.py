import hashlib
import re

from .constants import EXPECTED_LANES
from .io import canonical, digest, exact_fields, read_json, valid_hex
from .payloads import hosted_runner

def validate_candidate(source_root, source_revision, source_clean, candidate_root, block):
    manifest_path = candidate_root / "release-manifest.v1.json"
    manifest = read_json(manifest_path)
    required = {"format", "candidate", "artifacts", "profiles", "platforms", "evidence", "qualification_state"}
    if not isinstance(manifest, dict) or set(manifest) != required or manifest["format"] != "release-manifest.v1":
        raise ValueError("invalid manifest envelope")
    candidate = manifest["candidate"]
    if not exact_fields(candidate, ("source_revision", "release_version", "lockfile_digest", "qualification_lanes")):
        raise ValueError("invalid candidate tuple")
    if not valid_hex(candidate["source_revision"], 40) or not valid_hex(candidate["lockfile_digest"]):
        raise ValueError("invalid candidate digest")
    if candidate["source_revision"] != source_revision:
        block("source-integrity")
    if not source_clean:
        block("source-clean")
    if not isinstance(candidate["release_version"], str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?", candidate["release_version"]):
        raise ValueError("invalid release version")
    candidate_digest = hashlib.sha256(canonical(candidate).rstrip(b"\n")).hexdigest()
    if (source_root / "Cargo.lock").is_file() and digest(source_root / "Cargo.lock") != candidate["lockfile_digest"]:
        block("source-integrity")
    expected_lanes = EXPECTED_LANES
    lane_slots = {}
    if not isinstance(candidate["qualification_lanes"], list) or len(candidate["qualification_lanes"]) != 2:
        raise ValueError("invalid qualification lanes")
    for lane in candidate["qualification_lanes"]:
        if not exact_fields(lane, ("lane_id", "rustc_version", "cargo_version", "hosted_execution_slots")):
            raise ValueError("invalid qualification lane")
        lane_id = lane["lane_id"]
        if lane_id not in expected_lanes or lane["rustc_version"] != expected_lanes[lane_id] or lane["cargo_version"] != expected_lanes[lane_id]:
            raise ValueError("invalid toolchain lane")
        slots = lane["hosted_execution_slots"]
        if not isinstance(slots, list) or len(slots) != 3:
            raise ValueError("invalid hosted slots")
        lane_slots[lane_id] = {}
        for slot in slots:
            if not isinstance(slot, dict) or set(slot) not in ({"platform", "status"}, {"platform", "status", "hosted_runner"}):
                raise ValueError("invalid hosted slot")
            platform = slot.get("platform")
            if platform not in {"linux", "macos", "windows"} or platform in lane_slots[lane_id] or slot.get("status") not in {"planned", "actual"}:
                raise ValueError("invalid hosted slot identity")
            if slot["status"] == "actual" and not hosted_runner(slot.get("hosted_runner")):
                raise ValueError("missing hosted runner")
            if slot["status"] == "planned" and "hosted_runner" in slot:
                raise ValueError("planned slot has runner")
            lane_slots[lane_id][platform] = slot
    if set(lane_slots) != set(expected_lanes) or any(set(slots) != {"linux", "macos", "windows"} for slots in lane_slots.values()):
        raise ValueError("incomplete hosted slots")
    return manifest, candidate, candidate_digest, lane_slots
