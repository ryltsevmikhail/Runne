#!/usr/bin/env python3
"""Fail-closed native packaged application probe for protected CI runners."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as host_platform
import stat
import subprocess
import sys
from pathlib import Path

if __package__:
    from .native_package_commands import command as native_package_command
    from .native_runner_lifecycle import verify_admission_identity
    from .package_artifact_snapshot import ArtifactAdmissionError, ArtifactSnapshot, stage_artifact
    from .windows_package_snapshot import is_pinned_snapshot_path
else:
    from native_package_commands import command as native_package_command
    from native_runner_lifecycle import verify_admission_identity
    from package_artifact_snapshot import ArtifactAdmissionError, ArtifactSnapshot, stage_artifact
    from windows_package_snapshot import is_pinned_snapshot_path

ROOT = Path(__file__).resolve().parents[2]
PAIR_MATRIX = {
    "macos-14-arm64": {"os": "darwin", "arch": "arm64", "version": (14,), "bundle": "app", "required_bundles": ("app", "dmg")},
    "macos-13-x86_64": {"os": "darwin", "arch": "x86_64", "version": (13,), "bundle": "app", "required_bundles": ("app", "dmg")},
    "windows-10-22h2-x86_64": {"os": "windows", "arch": "amd64", "build": "19045", "bundle": "nsis", "required_bundles": ("nsis",)},
    "ubuntu-22.04-x86_64": {"os": "linux", "arch": "x86_64", "version": "22.04", "bundle": "deb", "required_bundles": ("appimage", "deb")},
}
OPERATIONS = ("install", "discover-installed-artifact", "executable-identity", "protected-launch", "protected-relaunch", "secure-store-writer-reader", "secure-store-third-process-deny", "signing-notarization", "uninstall")
MAIN_BINARY_NAME = "runne-desktop"
NON_APPLICABLE_OPERATIONS = {
    "ubuntu-22.04-x86_64": frozenset({"signing-notarization"}),
}


def current_platform() -> tuple[str, str]:
    system, arch = host_platform.system().lower(), host_platform.machine().lower()
    if arch in ("amd64", "x64"): arch = "x86_64" if system == "linux" else "amd64" if system == "windows" else arch
    return system, arch


def _host_version(system: str) -> str | None:
    if system == "darwin": return host_platform.mac_ver()[0] or None
    if system == "linux": return _lsb_release()
    return None


def _lsb_release() -> str | None:
    try:
        return next((line.split("=", 1)[1].strip().strip('"') for line in Path("/etc/os-release").read_text().splitlines() if line.startswith("VERSION_ID=")), None)
    except OSError: return None


def _version_matches(version: str, expected: object) -> bool:
    if isinstance(expected, tuple):
        try:
            return int(str(version).split(".", 1)[0]) >= expected[0]
        except (TypeError, ValueError):
            return False
    return str(version).startswith(expected) if isinstance(expected, str) else True


def _windows_build() -> str | None:
    return host_platform.version().split(".")[-1] if host_platform.system().lower() == "windows" else None


def _pair_blocker(pair: str) -> str:
    return "WINDOWS_SECURE_IDENTITY_UNVERIFIED" if pair.startswith("windows") else "LINUX_SECURE_IDENTITY_UNVERIFIED" if pair.startswith("ubuntu") else "MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED"


def preflight(pair: str, package_path: str | None = None) -> dict[str, object]:
    spec = PAIR_MATRIX.get(pair)
    if spec is None: return {"platform_id": pair, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED", "detail": f"unknown platform pair {pair!r}"}
    if package_path is not None and package_path != recompute_package_path(pair): return {"platform_id": pair, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED", "detail": "declared package path differs from Tauri configuration"}
    system, arch = current_platform()
    if system != spec["os"] or arch != spec["arch"]: return {"platform_id": pair, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED", "detail": f"host {system}/{arch} does not match {spec['os']}/{spec['arch']}"}
    version, expected = _host_version(system), spec.get("version")
    if expected is not None and (version is None or not _version_matches(version, expected)): return {"platform_id": pair, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED", "detail": "host version does not match required matrix"}
    if spec.get("build") is not None and _windows_build() != spec["build"]: return {"platform_id": pair, "disposition": "blocked", "blocker_code": "RUNNER_TRUST_UNVERIFIED", "detail": "host build does not match required matrix"}
    return {"platform_id": pair, "disposition": "blocked", "blocker_code": _pair_blocker(pair), "detail": "preflight passed; package probe and external provenance required"}


def recompute_package_path(pair: str, bundle: str | None = None) -> str | None:
    try: conf = json.loads((ROOT / "apps/desktop/src-tauri/tauri.conf.json").read_text())
    except (OSError, json.JSONDecodeError): return None
    product, version = conf.get("productName") or conf.get("package", {}).get("productName"), conf.get("version")
    bundle = bundle or PAIR_MATRIX.get(pair, {}).get("bundle")
    if not isinstance(product, str) or not isinstance(version, str): return None
    architecture = "aarch64" if pair == "macos-14-arm64" else "x64" if pair == "macos-13-x86_64" else "amd64"
    return f"target/release/bundle/macos/{product}.app" if bundle == "app" else f"target/release/bundle/dmg/{product}_{version}_{architecture}.dmg" if bundle == "dmg" else f"target/release/bundle/nsis/{product}_{version}_x64-setup.exe" if bundle == "nsis" else f"target/release/bundle/appimage/{product}_{version}_amd64.AppImage" if bundle == "appimage" else f"target/release/bundle/deb/{product}_{version}_amd64.deb" if bundle == "deb" else None


def required_package_paths(pair: str) -> set[str]:
    """Return every bundle format that must be probed for one target pair."""
    spec = PAIR_MATRIX.get(pair)
    return set(spec["required_bundles"]) if spec else set()


def required_native_operations(pair: str) -> tuple[str, ...]:
    """Return operations that must be verified for a mandatory platform."""
    excluded = NON_APPLICABLE_OPERATIONS.get(pair, frozenset())
    return tuple(operation for operation in OPERATIONS if operation not in excluded)


def _admit_package(pair: str, package: str | None) -> tuple[ArtifactSnapshot | None, list[ArtifactSnapshot], str | None]:
    spec = PAIR_MATRIX.get(pair)
    if spec is None or package is None:
        return None, [], "PACKAGE_ARTIFACT_MISSING"
    snapshots: list[ArtifactSnapshot] = []
    try:
        for bundle in spec["required_bundles"]:
            recomputed = recompute_package_path(pair, bundle)
            if bundle == spec["bundle"] and package != recomputed:
                raise ArtifactAdmissionError("PACKAGE_ARTIFACT_PATH_UNSAFE")
            snapshots.append(stage_artifact(ROOT, recomputed, bundle))
    except ArtifactAdmissionError as error:
        cleanup_error = None
        for snapshot in snapshots:
            try:
                snapshot.close()
            except Exception as close_error:
                cleanup_error = close_error
        return None, [], getattr(cleanup_error, "code", error.code)
    primary = next((item for item, bundle in zip(snapshots, spec["required_bundles"]) if bundle == spec["bundle"]), None)
    return primary, snapshots, None if primary is not None else "PACKAGE_ARTIFACT_PATH_UNRESOLVED"


def artifact_sha256(path: Path) -> str:
    """Hash one packaged file or canonical bundle tree, including relative paths."""
    digest = hashlib.sha256()
    if path.is_file(): return hashlib.sha256(path.read_bytes()).hexdigest()
    for child in sorted(path.rglob("*")):
        if child.is_file():
            digest.update(child.relative_to(path).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(child.read_bytes()).digest())
    return digest.hexdigest()


def _command(pair: str, operation: str, package: str) -> list[str]:
    return native_package_command(pair, operation, package, MAIN_BINARY_NAME)


def native_probe(pair: str, operation: str, package: str, snapshot: object | None = None, lease: object | None = None) -> dict[str, object]:
    """Run one real native adapter operation against the admitted snapshot."""
    if operation in NON_APPLICABLE_OPERATIONS.get(pair, frozenset()):
        return {"status": "not_applicable", "detail": "platform has no signing or notarization gate"}
    if snapshot is None or lease is None or not getattr(lease, "is_active_for", lambda _snapshot: False)(snapshot):
        return {"status": "blocked", "detail": "PACKAGE_ARTIFACT_SNAPSHOT_LEASE_REQUIRED"}
    options: dict[str, object] = {
        "check": False,
        "capture_output": True,
        "text": True,
        "timeout": 180,
    }
    if os.name == "nt":
        if not is_pinned_snapshot_path(package):
            return {"status": "blocked", "detail": "PACKAGE_ARTIFACT_PATH_UNSAFE"}
    elif os.name == "posix":
        prefix = "/dev/fd/"
        parts = package[len(prefix):].split("/") if package.startswith(prefix) else []
        if len(parts) != 1 or not parts[0].isdecimal():
            return {"status": "blocked", "detail": "PACKAGE_ARTIFACT_PATH_UNSAFE"}
        pinned_fd = int(parts[0])
        try:
            mode = os.fstat(pinned_fd).st_mode
            if not getattr(snapshot, "is_pinned_fd", lambda _fd: False)(pinned_fd):
                return {"status": "blocked", "detail": "PACKAGE_ARTIFACT_PATH_UNSAFE"}
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                return {"status": "blocked", "detail": "PACKAGE_ARTIFACT_PATH_UNSAFE"}
        except OSError:
            return {"status": "blocked", "detail": "PACKAGE_ARTIFACT_PATH_UNSAFE"}
        options["pass_fds"] = (pinned_fd,)
    else:
        return {"status": "blocked", "detail": "PACKAGE_ARTIFACT_PATH_UNSAFE"}
    result = subprocess.run(_command(pair, operation, package), **options)
    return {"status": "verified" if result.returncode == 0 else "blocked", "returncode": result.returncode, "detail": result.stderr.strip()}


def _probe_snapshot(pair: str, snapshot: object, evidence_path: Path, host_blocked: bool) -> tuple[str | None, dict[str, object], str | None]:
    try:
        with snapshot.acquire_use() as lease:
            snapshot_digest = getattr(snapshot, "sha256", None)
            digest = snapshot_digest() if callable(snapshot_digest) else artifact_sha256(snapshot.path)
            if host_blocked:
                return digest, {}, None
            install_root = evidence_path.parent / "native-package-probe-install"
            install_root.mkdir(mode=0o700, exist_ok=True)
            previous = os.environ.get("NATIVE_PROBE_INSTALL_ROOT")
            os.environ["NATIVE_PROBE_INSTALL_ROOT"] = str(install_root)
            try:
                operations = {operation: native_probe(pair, operation, str(snapshot.path), snapshot, lease) for operation in OPERATIONS}
            finally:
                if previous is None: os.environ.pop("NATIVE_PROBE_INSTALL_ROOT", None)
                else: os.environ["NATIVE_PROBE_INSTALL_ROOT"] = previous
            return digest, operations, None
    except Exception as error:
        return None, {}, getattr(error, "code", "PACKAGE_ARTIFACT_PATH_UNSAFE")


def run(pair: str, package: str | None, evidence_path: Path, runner_identity: Path | None = None, trust_root: Path | None = None, trust_root_sha256: str | None = None, job_id: str | None = None, workflow_run_id: str | None = None) -> int:
    pre, actual = preflight(pair, package), None
    actual, snapshots, package_blocker = _admit_package(pair, package)
    if package_blocker:
        pre["detail"] = f"{pre['detail']}; {package_blocker}"
    try: identity = json.loads(runner_identity.read_text(encoding="utf-8")) if runner_identity else {}
    except (OSError, json.JSONDecodeError): identity = {}
    admission = identity.get("admission") if trust_root and trust_root_sha256 and job_id and workflow_run_id and verify_admission_identity(identity, str(trust_root), trust_root_sha256, pair, job_id, workflow_run_id) else None
    admission_digest = identity.get("admission_sha256") if isinstance(admission, dict) else None
    if not isinstance(admission_digest, str) or admission_digest != hashlib.sha256(json.dumps(admission, sort_keys=True, separators=(",", ":")).encode()).hexdigest() or any(identity.get(key) != admission.get(key) for key in ("job_id", "workflow_run_id")):
        admission = None
    operations: dict[str, object] = {}
    cleanup_blocker: str | None = None
    try:
        snapshot_blocker = None
        digest = None
        if actual:
            digest, operations, snapshot_blocker = _probe_snapshot(pair, actual, evidence_path, pre["detail"].startswith("host "))
            if snapshot_blocker:
                pre["detail"] = f"{pre['detail']}; {snapshot_blocker}"
        for snapshot in snapshots:
            try:
                snapshot.close()
            except Exception as error:
                cleanup_blocker = getattr(error, "code", "PACKAGE_ARTIFACT_PATH_UNSAFE")
        if cleanup_blocker:
            snapshot_blocker = cleanup_blocker
            pre["detail"] = f"{pre['detail']}; {cleanup_blocker}"
        required = required_native_operations(pair)
        verified = isinstance(admission, dict) and actual is not None and bool(operations) and all(operations.get(operation, {}).get("status") == "verified" for operation in required) and all(operations.get(operation, {}).get("status") == "not_applicable" for operation in NON_APPLICABLE_OPERATIONS.get(pair, frozenset()))
        row = {"schema_version": "desktop-native-platform-foundation.v1", "platform_id": pair, "disposition": "verified" if verified else "blocked",
           "blocker_code": pre["blocker_code"], "detail": pre["detail"], "package": package, "package_present": actual is not None, "native_operations": operations,
           "artifact_sha256": digest,
           "source_ref": os.environ.get("SOURCECRAFT_COMMIT_SHA"), "canonical_source_content_sha256": os.environ.get("GOCODE_CANONICAL_SOURCE_CONTENT_SHA256"),
           "runner": {"runner_id": None, "instance_id": admission.get("instance_id") if isinstance(admission, dict) else None, "image_sha256": admission.get("image_sha256") if isinstance(admission, dict) else None, "boot_measurement_sha256": admission.get("boot_measurement_sha256") if isinstance(admission, dict) else None, "job_id": admission.get("job_id") if isinstance(admission, dict) else None, "workflow_run_id": admission.get("workflow_run_id") if isinstance(admission, dict) else None, "admission_sha256": admission_digest if isinstance(admission, dict) else None, "admission_issued_at": admission.get("issued_at") if isinstance(admission, dict) else None, "admission_expires_at": admission.get("expires_at") if isinstance(admission, dict) else None}}
        if verified: row["blocker_code"] = None
        elif not isinstance(admission, dict): row["blocker_code"] = "RUNNER_TRUST_UNVERIFIED"
        elif not row["package_present"] or any(value.get("status") != "verified" for value in operations.values()): row["blocker_code"] = "RUNNER_TRUST_UNVERIFIED" if pre["blocker_code"] == "RUNNER_TRUST_UNVERIFIED" else _pair_blocker(pair)
        if cleanup_blocker: row["blocker_code"] = cleanup_blocker
        evidence_path.write_text(json.dumps(row, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    finally:
        for snapshot in snapshots:
            snapshot.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest="command", required=True)
    pre = commands.add_parser("preflight"); pre.add_argument("--platform-pair", required=True); pre.add_argument("--package")
    run_p = commands.add_parser("run"); run_p.add_argument("--platform-pair", required=True); run_p.add_argument("--package"); run_p.add_argument("--evidence", type=Path, required=True); run_p.add_argument("--runner-identity", type=Path); run_p.add_argument("--trust-root", type=Path); run_p.add_argument("--trust-root-sha256"); run_p.add_argument("--job-id", required=True); run_p.add_argument("--workflow-run-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "preflight": print(json.dumps(preflight(args.platform_pair, args.package), sort_keys=True)); return 0
    return run(args.platform_pair, args.package, args.evidence, args.runner_identity, args.trust_root, args.trust_root_sha256, args.job_id, args.workflow_run_id)


if __name__ == "__main__": sys.exit(main())
