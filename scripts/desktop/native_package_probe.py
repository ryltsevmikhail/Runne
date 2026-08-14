#!/usr/bin/env python3
"""Fail-closed native packaged application probe for protected CI runners."""

import argparse
import hashlib
import json
import os
import platform as host_platform
import shlex
import subprocess
import sys
from pathlib import Path

if __package__:
    from .native_runner_lifecycle import verify_admission_identity
else:
    from native_runner_lifecycle import verify_admission_identity

ROOT = Path(__file__).resolve().parents[2]
PAIR_MATRIX = {
    "macos-13-arm64": {"os": "darwin", "arch": "arm64", "version": (13,), "bundle": "app"},
    "macos-13-x86_64": {"os": "darwin", "arch": "x86_64", "version": (13,), "bundle": "app"},
    "windows-10-22h2-x86_64": {"os": "windows", "arch": "amd64", "build": "19045", "bundle": "nsis"},
    "ubuntu-22.04-x86_64": {"os": "linux", "arch": "x86_64", "version": "22.04", "bundle": "deb"},
}
OPERATIONS = ("install", "discover-installed-artifact", "executable-identity", "protected-launch", "protected-relaunch", "secure-store-writer-reader", "secure-store-third-process-deny", "signing-notarization", "uninstall")


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
    return str(version).startswith(f"{expected[0]}.") if isinstance(expected, tuple) else str(version).startswith(expected) if isinstance(expected, str) else True


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
    return f"target/release/bundle/macos/{product}.app" if bundle == "app" else f"target/release/bundle/nsis/{product}_{version}_x64-setup.exe" if bundle == "nsis" else f"target/release/bundle/deb/{product}_{version}_amd64.deb" if bundle == "deb" else None


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
    quoted = shlex.quote(package)
    mac = {"install": f"ditto {quoted} \"$NATIVE_PROBE_INSTALL_ROOT/GOCODE.app\"", "discover-installed-artifact": "test -d \"$NATIVE_PROBE_INSTALL_ROOT/GOCODE.app\"", "executable-identity": "codesign -dvv \"$NATIVE_PROBE_INSTALL_ROOT/GOCODE.app\"", "signing-notarization": "codesign --verify --deep --strict \"$NATIVE_PROBE_INSTALL_ROOT/GOCODE.app\" && spctl --assess --type execute \"$NATIVE_PROBE_INSTALL_ROOT/GOCODE.app\"", "uninstall": "rm -rf \"$NATIVE_PROBE_INSTALL_ROOT/GOCODE.app\""}
    linux = {"install": f"dpkg --root \"$NATIVE_PROBE_INSTALL_ROOT\" --admindir \"$NATIVE_PROBE_INSTALL_ROOT/var/lib/dpkg\" --instdir \"$NATIVE_PROBE_INSTALL_ROOT\" -i {quoted}", "discover-installed-artifact": "find \"$NATIVE_PROBE_INSTALL_ROOT\" -type f -name GOCODE -print -quit | grep -q .", "executable-identity": "find \"$NATIVE_PROBE_INSTALL_ROOT\" -type f -name GOCODE -exec sha256sum {} \\;", "signing-notarization": "false", "uninstall": "rm -rf \"$NATIVE_PROBE_INSTALL_ROOT\"/*"}
    windows = {"install": f"Start-Process -Wait -FilePath '{package.replace("'", "''")}' -ArgumentList '/S'", "discover-installed-artifact": "Get-ChildItem $env:ProgramFiles -Filter GOCODE.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object {$_.FullName}", "executable-identity": "Get-AuthenticodeSignature (Get-ChildItem $env:ProgramFiles -Filter GOCODE.exe -Recurse | Select-Object -First 1).FullName", "signing-notarization": "(Get-AuthenticodeSignature (Get-ChildItem $env:ProgramFiles -Filter GOCODE.exe -Recurse | Select-Object -First 1).FullName).Status -eq 'Valid'", "uninstall": "Get-ChildItem $env:ProgramFiles -Filter unins*.exe -Recurse | Select-Object -First 1 | ForEach-Object {Start-Process -Wait -FilePath $_.FullName -ArgumentList '/S'}"}
    if pair.startswith("macos"): return ["/usr/bin/env", "bash", "-lc", mac[operation]]
    if pair.startswith("windows"): return ["powershell", "-NoProfile", "-Command", windows[operation]]
    return ["/usr/bin/env", "bash", "-lc", linux[operation]]


def native_probe(pair: str, operation: str, package: str) -> dict[str, object]:
    """Run one real native adapter operation; caller remains blocked without CI proof."""
    if operation in {"protected-launch", "protected-relaunch", "secure-store-writer-reader", "secure-store-third-process-deny"}:
        return {"status": "blocked", "detail": "PACKAGED_NATIVE_PROBE_SURFACE_NOT_IMPLEMENTED"}
    result = subprocess.run(_command(pair, operation, package), check=False, capture_output=True, text=True)
    return {"status": "verified" if result.returncode == 0 else "blocked", "returncode": result.returncode, "detail": result.stderr.strip()}


def run(pair: str, package: str | None, evidence_path: Path, runner_identity: Path | None = None, trust_root: Path | None = None, trust_root_sha256: str | None = None, job_id: str | None = None, workflow_run_id: str | None = None) -> int:
    pre, actual = preflight(pair, package), Path(package) if package else None
    try: identity = json.loads(runner_identity.read_text(encoding="utf-8")) if runner_identity else {}
    except (OSError, json.JSONDecodeError): identity = {}
    admission = identity.get("admission") if trust_root and trust_root_sha256 and job_id and workflow_run_id and verify_admission_identity(identity, str(trust_root), trust_root_sha256, pair, job_id, workflow_run_id) else None
    admission_digest = identity.get("admission_sha256") if isinstance(admission, dict) else None
    if not isinstance(admission_digest, str) or admission_digest != hashlib.sha256(json.dumps(admission, sort_keys=True, separators=(",", ":")).encode()).hexdigest() or any(identity.get(key) != admission.get(key) for key in ("job_id", "workflow_run_id")):
        admission = None
    operations: dict[str, object] = {}
    if actual and actual.exists() and not pre["detail"].startswith("host "):
        install_root = evidence_path.parent / "native-package-probe-install"
        install_root.mkdir(mode=0o700, exist_ok=True)
        previous = os.environ.get("NATIVE_PROBE_INSTALL_ROOT")
        os.environ["NATIVE_PROBE_INSTALL_ROOT"] = str(install_root)
        try: operations = {operation: native_probe(pair, operation, str(actual)) for operation in OPERATIONS}
        finally:
            if previous is None: os.environ.pop("NATIVE_PROBE_INSTALL_ROOT", None)
            else: os.environ["NATIVE_PROBE_INSTALL_ROOT"] = previous
    row = {"schema_version": "desktop-native-platform-foundation.v1", "platform_id": pair, "disposition": "blocked",
           "blocker_code": pre["blocker_code"], "detail": pre["detail"], "package": package, "package_present": bool(actual and actual.exists()), "native_operations": operations,
           "artifact_sha256": artifact_sha256(actual) if actual and actual.exists() else None,
           "source_ref": os.environ.get("GITHUB_SHA"), "canonical_source_content_sha256": os.environ.get("GOCODE_CANONICAL_SOURCE_CONTENT_SHA256"),
           "runner": {"runner_id": None, "instance_id": admission.get("instance_id") if isinstance(admission, dict) else None, "image_sha256": admission.get("image_sha256") if isinstance(admission, dict) else None, "boot_measurement_sha256": admission.get("boot_measurement_sha256") if isinstance(admission, dict) else None, "job_id": admission.get("job_id") if isinstance(admission, dict) else None, "workflow_run_id": admission.get("workflow_run_id") if isinstance(admission, dict) else None, "admission_sha256": admission_digest if isinstance(admission, dict) else None, "admission_issued_at": admission.get("issued_at") if isinstance(admission, dict) else None, "admission_expires_at": admission.get("expires_at") if isinstance(admission, dict) else None}}
    if not isinstance(admission, dict): row["blocker_code"] = "RUNNER_TRUST_UNVERIFIED"
    if not row["package_present"] or any(value.get("status") != "verified" for value in operations.values()): row["blocker_code"] = "RUNNER_TRUST_UNVERIFIED" if pre["blocker_code"] == "RUNNER_TRUST_UNVERIFIED" else _pair_blocker(pair)
    evidence_path.write_text(json.dumps(row, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest="command", required=True)
    pre = commands.add_parser("preflight"); pre.add_argument("--platform-pair", required=True); pre.add_argument("--package")
    run_p = commands.add_parser("run"); run_p.add_argument("--platform-pair", required=True); run_p.add_argument("--package"); run_p.add_argument("--evidence", type=Path, required=True); run_p.add_argument("--runner-identity", type=Path); run_p.add_argument("--trust-root", type=Path); run_p.add_argument("--trust-root-sha256"); run_p.add_argument("--job-id", required=True); run_p.add_argument("--workflow-run-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "preflight": print(json.dumps(preflight(args.platform_pair, args.package), sort_keys=True)); return 0
    return run(args.platform_pair, args.package, args.evidence, args.runner_identity, args.trust_root, args.trust_root_sha256, args.job_id, args.workflow_run_id)


if __name__ == "__main__": sys.exit(main())
