#!/usr/bin/env python3
"""Fail-closed structural smoke checks for native Desktop package outputs."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__:
    from .native_package_probe import MAIN_BINARY_NAME, PAIR_MATRIX, recompute_package_path, required_package_paths
    from .package_artifact_snapshot import ArtifactAdmissionError, stage_artifact
else:
    from native_package_probe import MAIN_BINARY_NAME, PAIR_MATRIX, recompute_package_path, required_package_paths
    from package_artifact_snapshot import ArtifactAdmissionError, stage_artifact

ROOT = Path(__file__).resolve().parents[2]
TAURI_CONFIG = ROOT / "apps/desktop/src-tauri/tauri.conf.json"


def _load_config() -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    value = json.loads(TAURI_CONFIG.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("Tauri configuration must be an object")
    return value


def _bundled_daemon(config: dict[str, object]) -> bool:
    bundle = config.get("bundle")
    if not isinstance(bundle, dict):
        return False
    values = bundle.get("externalBin")
    return isinstance(values, list) and any(isinstance(value, str) and Path(value).name == "runned" for value in values)


def _manifest_blockers(config: dict[str, object]) -> list[str]:
    blockers: list[str] = []
    identifier = config.get("identifier")
    if not isinstance(identifier, str) or identifier.startswith("dev."):
        blockers.append("DEVELOPMENT_IDENTIFIER")
    if config.get("mainBinaryName") != MAIN_BINARY_NAME:
        blockers.append("MAIN_BINARY_NAME_INVALID")
    bundle = config.get("bundle")
    if not isinstance(bundle, dict) or bundle.get("active") is not True or bundle.get("targets") != "all":
        blockers.append("PACKAGE_TARGETS_NOT_CONFIGURED")
    if not _bundled_daemon(config):
        blockers.append("BUNDLED_DAEMON_NOT_CONFIGURED")
    icons = bundle.get("icon") if isinstance(bundle, dict) else None
    if not isinstance(icons, list) or not icons or any(not isinstance(item, str) or not (TAURI_CONFIG.parent / item).is_file() for item in icons):
        blockers.append("PACKAGE_ICONS_INVALID")
    macos = bundle.get("macOS") if isinstance(bundle, dict) else None
    if not isinstance(macos, dict) or macos.get("minimumSystemVersion") != "13.0" or macos.get("hardenedRuntime") is not True:
        blockers.append("MACOS_RELEASE_POLICY_INVALID")
    windows = bundle.get("windows") if isinstance(bundle, dict) else None
    if not isinstance(windows, dict) or windows.get("allowDowngrades") is not False or windows.get("digestAlgorithm") != "sha256" or not isinstance(windows.get("timestampUrl"), str) or not windows["timestampUrl"].startswith("https://"):
        blockers.append("WINDOWS_RELEASE_POLICY_INVALID")
    return blockers


def _artifact_state(bundle: str, relative_path: str | None) -> tuple[dict[str, object], str | None]:
    expected = "directory" if bundle == "app" else "regular_file"
    if not isinstance(relative_path, str):
        return {"path": None, "present": False, "expected_type": expected}, "PACKAGE_ARTIFACT_PATH_UNRESOLVED"
    try:
        snapshot = stage_artifact(ROOT, relative_path, bundle)
    except ArtifactAdmissionError as error:
        return {"path": relative_path, "present": False, "expected_type": expected}, error.code
    try:
        snapshot.close()
    except Exception as error:
        return {"path": relative_path, "present": False, "expected_type": expected}, getattr(error, "code", "PACKAGE_ARTIFACT_PATH_UNSAFE")
    state = {"path": relative_path, "present": True, "expected_type": expected}
    return state, None


def smoke(platform: str) -> dict[str, object]:
    """Inspect immutable build inputs; never mint platform qualification evidence."""
    if platform not in PAIR_MATRIX:
        return {"platform": platform, "disposition": "blocked", "blockers": ["UNKNOWN_PLATFORM"]}
    try:
        config = _load_config()
    except (OSError, ValueError, json.JSONDecodeError):
        return {"platform": platform, "disposition": "blocked", "blockers": ["TAURI_CONFIG_INVALID"]}
    blockers = _manifest_blockers(config)
    artifacts: dict[str, dict[str, object]] = {}
    for bundle in sorted(required_package_paths(platform)):
        state, blocker = _artifact_state(bundle, recompute_package_path(platform, bundle))
        artifacts[bundle] = state
        if blocker and blocker not in blockers:
            blockers.append(blocker)
    return {
        "platform": platform,
        "disposition": "blocked" if blockers else "structurally_valid",
        "blockers": blockers,
        "artifacts": artifacts,
        "qualification": "native install, launch, secure-store and signing probes still required",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=sorted(PAIR_MATRIX))
    args = parser.parse_args(argv)
    result = smoke(args.platform)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["disposition"] == "structurally_valid" else 1


if __name__ == "__main__":
    sys.exit(main())
