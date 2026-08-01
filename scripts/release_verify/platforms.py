from .io import exact_fields, valid_hex

def validate_platforms(manifest, artifacts, artifact_digests, profile_digests):
    platforms = manifest["platforms"]
    if not isinstance(platforms, list) or not platforms:
        raise ValueError("missing platform bindings")
    allowed_targets = {"linux": {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}, "macos": {"aarch64-apple-darwin", "x86_64-apple-darwin"}, "windows": {"x86_64-pc-windows-msvc"}}
    platform_keys = set()
    platform_artifacts = {}
    platform_targets = {}
    for platform in platforms:
        if not exact_fields(platform, ("os", "target", "artifact_sha256", "profile_digests")) or platform["os"] not in {"linux", "macos", "windows"} or not valid_hex(platform["artifact_sha256"]) or platform["artifact_sha256"] not in artifact_digests or platform["artifact_sha256"] not in artifact_digests or platform["profile_digests"] != profile_digests:
            raise ValueError("invalid platform binding")
        if platform["target"] not in allowed_targets[platform["os"]]:
            raise ValueError("invalid platform target")
        key = (platform["os"], platform["target"])
        if key in platform_keys:
            raise ValueError("duplicate platform binding")
        if platform["os"] in platform_artifacts or platform["artifact_sha256"] in platform_artifacts.values():
            raise ValueError("platform artifact binding is reused")
        if not any(artifact["sha256"] == platform["artifact_sha256"] and artifact["target"] == platform["target"] for artifact in artifacts):
            raise ValueError("platform target does not match its artifact")
        platform_keys.add(key)
        platform_artifacts[platform["os"]] = platform["artifact_sha256"]
        platform_targets[platform["os"]] = platform["target"]
    qualification_state = manifest["qualification_state"]
    if qualification_state not in {"draft", "assembled", "verified", "review-pending", "approved", "blocked"}:
        raise ValueError("invalid qualification state")
    if qualification_state != "assembled" and set(platform_artifacts) != {"linux", "macos", "windows"}:
        raise ValueError("incomplete platform artifact bindings")
    return platform_artifacts, platform_targets, qualification_state
