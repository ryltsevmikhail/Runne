#!/usr/bin/env python3
"""Fail-closed source-bound Desktop V1 native qualification validator."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

if __package__:
    from .capability_manifest_impl.io import SOURCECRAFT_ATTEST_VERIFIER_PATH, canonical_source_content_digest, evidence_only_difference
else:
    from capability_manifest_impl.io import SOURCECRAFT_ATTEST_VERIFIER_PATH, canonical_source_content_digest, evidence_only_difference

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "docs/schemas/desktop-native-platform-foundation-v1.schema.json"
EVIDENCE_PATH = ROOT / "docs/evidence/desktop-native-platform-foundation-v1.json"
IN_TOTO_PATH = ROOT / "docs/evidence/desktop-native-platform-foundation-v1.intoto.jsonl"
MANDATORY_PLATFORMS = ("MACOS-13-ARM64", "MACOS-13-X86-64", "WINDOWS-10-22H2-X86-64", "LINUX-UBUNTU-22-04-X86-64")
PAIR_IDS = {"macos-13-arm64": MANDATORY_PLATFORMS[0], "macos-13-x86_64": MANDATORY_PLATFORMS[1], "windows-10-22h2-x86_64": MANDATORY_PLATFORMS[2], "ubuntu-22.04-x86_64": MANDATORY_PLATFORMS[3]}
SPECIFIC_BLOCKERS = frozenset({"WINDOWS_SECURE_IDENTITY_UNVERIFIED", "WINDOWS_PROTECTED_LAUNCH_UNVERIFIED", "LINUX_SECURE_IDENTITY_UNVERIFIED", "LINUX_PROTECTED_LAUNCH_UNVERIFIED", "MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED", "RUNNER_TRUST_UNVERIFIED"})
ALLOWED_BLOCKERS = {MANDATORY_PLATFORMS[0]: frozenset({"MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED"}), MANDATORY_PLATFORMS[1]: frozenset({"MACOS_STAGED_DAEMON_IDENTITY_UNVERIFIED"}), MANDATORY_PLATFORMS[2]: frozenset({"WINDOWS_SECURE_IDENTITY_UNVERIFIED", "WINDOWS_PROTECTED_LAUNCH_UNVERIFIED"}), MANDATORY_PLATFORMS[3]: frozenset({"LINUX_SECURE_IDENTITY_UNVERIFIED", "LINUX_PROTECTED_LAUNCH_UNVERIFIED"})}
SIMULATED_MARKERS = ("simulated", "stub", "synthetic", "loopback", "fixture", "fake", "mock", "test-double")
UNTRUSTED_SIGNING_MARKERS = ("ad-hoc", "adhoc", "self-signed", "unsigned")
SOURCECRAFT_NATIVE_VERIFIER_PATH = SOURCECRAFT_ATTEST_VERIFIER_PATH
SOURCECRAFT_REPOSITORY = "https://git@git.sourcecraft.dev/ryltsevmg/runne.git"


def load_json(path: Path) -> dict[str, object]:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def artifact_sha256(path: Path) -> str:
    if path.is_file(): return hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256()
    for child in sorted(path.rglob("*")):
        if child.is_file():
            digest.update(child.relative_to(path).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(child.read_bytes()).digest())
    return digest.hexdigest()


def _verified_row_errors(row: dict[str, object]) -> list[str]:
    errors, platform = [], row.get("platform_id")
    if not all(is_sha256(row.get(key)) for key in ("source_sha256", "artifact_sha256")): errors.append(f"{platform}: verified row missing source/artifact digest")
    runner, executable, daemon, provenance = row.get("runner"), row.get("packaged_executable"), row.get("staged_daemon"), row.get("provenance")
    if not isinstance(runner, dict) or not all(is_sha256(runner.get(key)) for key in ("image_sha256", "boot_measurement_sha256")) or not all(isinstance(runner.get(key), str) and runner[key] for key in ("instance_id", "job_id")): errors.append(f"{platform}: verified row missing measured ephemeral runner")
    if not isinstance(executable, dict) or not is_sha256(executable.get("identity_sha256")) or not isinstance(executable.get("signing_identity"), str): errors.append(f"{platform}: verified row missing packaged executable identity")
    if not isinstance(daemon, dict) or not is_sha256(daemon.get("identity_sha256")) or not isinstance(daemon.get("signing_identity"), str): errors.append(f"{platform}: verified row missing staged daemon identity")
    if str(platform).startswith("MACOS-") and row.get("notarization") != "verified": errors.append(f"{platform}: verified macOS row missing notarization")
    if not isinstance(provenance, dict) or not all(is_sha256(provenance.get(key)) for key in ("subject_sha256", "predicate_sha256", "canonical_source_content_sha256")) or not all(isinstance(provenance.get(key), str) and provenance[key] for key in ("issuer", "repository", "workflow", "ref", "source_ref")): errors.append(f"{platform}: verified row missing signed provenance")
    for key in ("secure_store_probe", "protected_launch_probe"):
        value = row.get(key)
        if not isinstance(value, dict) or value.get("status") != "verified": errors.append(f"{platform}: verified row missing {key} evidence")
        elif any(marker in str(value.get("detail") or "").lower() for marker in SIMULATED_MARKERS): errors.append(f"{platform}: simulated {key} evidence rejected")
    signing = executable.get("signing_identity") if isinstance(executable, dict) else None
    if not isinstance(signing, str) or any(marker in signing.lower() for marker in UNTRUSTED_SIGNING_MARKERS): errors.append(f"{platform}: ad-hoc or simulated signing identity rejected")
    return errors


def row_errors(row: dict[str, object]) -> list[str]:
    platform, disposition = row.get("platform_id"), row.get("disposition")
    if platform not in ALLOWED_BLOCKERS: return [f"unknown platform_id {platform!r}"]
    if disposition == "verified": return _verified_row_errors(row)
    if disposition not in ("blocked", "unsupported", "incompatible"): return [f"invalid disposition {disposition!r}"]
    errors = []
    if row.get("blocker_code") not in ALLOWED_BLOCKERS[platform] and row.get("blocker_code") != "RUNNER_TRUST_UNVERIFIED": errors.append(f"{platform}: non-specific blocker_code {row.get('blocker_code')!r}")
    if row.get("profile_sha256") != row.get("bundle_sha256"): errors.append(f"{platform}: profile and bundle digests disagree")
    if row.get("artifact_sha256") is not None: errors.append(f"{platform}: blocked row must not carry artifact_sha256")
    return errors


def validate_evidence(evidence: object) -> list[str]:
    if not isinstance(evidence, dict): return ["evidence is not an object"]
    if evidence.get("schema_version") != "desktop-native-platform-foundation.v1" or evidence.get("manifest_id") != "desktop-v1": return ["invalid evidence identity"]
    rows = evidence.get("platforms")
    if not isinstance(rows, list) or len(rows) != 4: return ["platforms array must contain exactly the mandatory matrix"]
    errors = [error for row in rows if isinstance(row, dict) for error in row_errors(row)]
    if any(not isinstance(row, dict) for row in rows) or sorted(row.get("platform_id") for row in rows if isinstance(row, dict)) != sorted(MANDATORY_PLATFORMS): errors.append("platform matrix does not match the mandatory OS/version/architecture set")
    return errors


def _policy_from_env() -> dict[str, str] | None:
    keys = {"repository": "SOURCECRAFT_REPO_URL", "workflow": "SOURCECRAFT_WORKFLOW", "ref": "SOURCECRAFT_COMMIT_REF"}
    policy = {key: os.environ.get(env, "") for key, env in keys.items()}
    return policy if os.environ.get("SOURCECRAFT_CI") == "true" and policy["repository"] == SOURCECRAFT_REPOSITORY and all(policy.values()) and policy["ref"].startswith("refs/") else None


def _verified_predicate(result: object, subject_sha256: str, source_ref: str, policy: dict[str, str]) -> dict[str, object] | None:
    required = {"verified", "subject_sha256", "repository", "workflow", "source_ref", "source_digest", "predicate"}
    if not isinstance(result, dict) or set(result) != required or result["verified"] is not True or result["subject_sha256"] != subject_sha256:
        return None
    if result["repository"] != policy["repository"] or result["workflow"] != policy["workflow"] or result["source_ref"] != policy["ref"] or result["source_digest"] != source_ref or not isinstance(result["predicate"], dict):
        return None
    return result["predicate"]


def verify_provenance_payload(evidence: object, package_sha256: str, source_ref: str | None, policy: dict[str, str] | None, gate: object, evidence_sha256: str | None = None) -> list[str]:
    if not isinstance(evidence, dict) or policy is None or not isinstance(source_ref, str) or len(source_ref) != 40 or not all(char in "0123456789abcdef" for char in source_ref) or not is_sha256(package_sha256) or not is_sha256(evidence_sha256) or evidence.get("source_ref") != source_ref or evidence.get("artifact_sha256") != package_sha256 or not isinstance(gate, dict): return ["RUNNER_TRUST_UNVERIFIED"]
    package_predicate = _verified_predicate(gate.get("package"), package_sha256, source_ref, policy)
    evidence_predicate = _verified_predicate(gate.get("evidence"), evidence_sha256, source_ref, policy)
    return [] if package_predicate is not None and evidence_predicate is not None else ["RUNNER_TRUST_UNVERIFIED"]


def _verify_bundle(package: Path, bundle: Path, policy: dict[str, str], source_ref: str) -> object | None:
    verifier = SOURCECRAFT_NATIVE_VERIFIER_PATH
    if set(policy) != {"repository", "workflow", "ref"} or policy["repository"] != SOURCECRAFT_REPOSITORY or not policy["workflow"] or not policy["ref"].startswith("refs/") or not verifier.is_file() or not os.access(verifier, os.X_OK): return None
    command = [str(verifier), "verify", "--subject", str(package), "--bundle", str(bundle), "--repository", policy["repository"], "--workflow", policy["workflow"], "--source-ref", policy["ref"], "--source-digest", source_ref, "--format", "json"]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        return json.loads(result.stdout) if result.returncode == 0 else None
    except (FileNotFoundError, OSError, TypeError, ValueError): return None


def verify_provenance_command(package: Path | None, evidence: Path | None, source_ref: str | None, gate_bundle: Path | None, output: Path | None) -> int:
    try:
        package_sha = artifact_sha256(package) if package and package.exists() else ""
        value = load_json(evidence) if evidence else {}
        policy = _policy_from_env()
        evidence_sha = hashlib.sha256(evidence.read_bytes()).hexdigest() if evidence and evidence.is_file() else ""
        gate = {"package": _verify_bundle(package, gate_bundle, policy, source_ref), "evidence": _verify_bundle(evidence, gate_bundle, policy, source_ref)} if package and evidence and gate_bundle and policy and source_ref else {}
        errors = verify_provenance_payload(value, package_sha, source_ref, policy, gate, evidence_sha)
        reviewed = value.get("reviewed_source_ref") if isinstance(value, dict) else None
        if not errors and (value.get("canonical_source_content_sha256") != canonical_source_content_digest(ROOT, source_ref) or (isinstance(reviewed, str) and reviewed != source_ref and not evidence_only_difference(ROOT, reviewed, source_ref))): errors = ["RUNNER_TRUST_UNVERIFIED"]
    except (OSError, ValueError, subprocess.CalledProcessError): errors = ["RUNNER_TRUST_UNVERIFIED"]
    if output and not errors: output.write_text(json.dumps({"schema_version": "desktop-native-attestation-verification.v1", "verified": True, "package_sha256": package_sha, "evidence_sha256": evidence_sha, "source_ref": source_ref, "policy": policy, "verification": gate}, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"verified": not errors, "errors": errors}, sort_keys=True)); return 0 if not errors else 1


def verify_provenance_errors(source_ref: str | None) -> list[str]:
    return ["RUNNER_TRUST_UNVERIFIED: provenance requires protected SourceCraft CI"] if source_ref or not IN_TOTO_PATH.exists() or not _policy_from_env() else ["RUNNER_TRUST_UNVERIFIED: SourceCraft attestation verification required"]


def _provisional_row(probe: dict[str, object], verification: dict[str, object]) -> dict[str, object]:
    platform = PAIR_IDS.get(str(probe.get("platform_id")), probe.get("platform_id"))
    return {"platform_id": platform, "disposition": "blocked", "blocker_code": probe.get("blocker_code") or "RUNNER_TRUST_UNVERIFIED", "verification": verification, "runner": probe.get("runner", {}), "probe": probe}


def build_row(probe_path: Path, gate_bundle_path: Path | None, output: Path) -> int:
    try:
        probe = load_json(probe_path)
        verification = load_json(gate_bundle_path) if gate_bundle_path else {}
        required = {"schema_version", "verified", "package_sha256", "evidence_sha256", "source_ref", "policy", "verification"}
        if set(verification) != required or verification.get("schema_version") != "desktop-native-attestation-verification.v1" or verification.get("verified") is not True or verification.get("evidence_sha256") != hashlib.sha256(probe_path.read_bytes()).hexdigest() or verification.get("package_sha256") != probe.get("artifact_sha256"): raise ValueError("closed verified attestation receipt absent")
    except (OSError, ValueError) as error:
        print(f"build-row: invalid input: {error}", file=sys.stderr); return 1
    output.write_text(json.dumps(_provisional_row(probe, verification), sort_keys=True, indent=2) + "\n", encoding="utf-8"); return 0


def assemble_status(rows_dir: Path, runner_lifecycle: Path | None, base: Path | None, output: Path) -> int:
    try:
        rows = [load_json(path) for path in sorted(rows_dir.rglob("native-platform-row.json"))] if rows_dir.is_dir() else []
        lifecycle, status = load_json(runner_lifecycle) if runner_lifecycle else {}, load_json(base) if base else {}
        ids = [row.get("platform_id") for row in rows]
        canonical_rows = json.dumps(sorted(rows, key=lambda row: str(row.get("platform_id"))), sort_keys=True, separators=(",", ":"))
        lifecycle_rows = lifecycle.get("rows") if isinstance(lifecycle, dict) else None
        canonical_lifecycle = json.dumps(sorted(lifecycle_rows, key=lambda row: str(row.get("platform_id"))) if isinstance(lifecycle_rows, list) else [], sort_keys=True, separators=(",", ":"))
        if not isinstance(lifecycle, dict) or lifecycle.get("verified") is not True or canonical_rows != canonical_lifecycle or set(lifecycle.get("platforms", [])) != set(MANDATORY_PLATFORMS) or sorted(ids) != sorted(MANDATORY_PLATFORMS) or status.get("schema_version") != "desktop-v1-capability-status.v2": raise ValueError("incomplete, swapped, duplicate, or unverified native evidence")
        status["platforms"] = [{"platform_id": row["platform_id"], "disposition": row["disposition"], "blocker_code": row["blocker_code"]} for row in sorted(rows, key=lambda row: str(row["platform_id"]))]
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"assemble-status: {error}", file=sys.stderr); return 1
    output.write_text(json.dumps(status, sort_keys=True, indent=2) + "\n", encoding="utf-8"); return 0


def validate(source_ref: str | None = None, verify_provenance: bool = False) -> int:
    errors = validate_evidence(load_json(EVIDENCE_PATH)); result = {"valid": not errors, "errors": errors}
    if verify_provenance: result.update(provenance_verified=False, provenance_blockers=verify_provenance_errors(source_ref))
    print(json.dumps(result, sort_keys=True)); return 0 if not errors else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest="command", required=True)
    val = commands.add_parser("validate"); val.add_argument("--source-ref"); val.add_argument("--verify-provenance", action="store_true")
    vp = commands.add_parser("verify-provenance"); vp.add_argument("--package", type=Path); vp.add_argument("--evidence", type=Path); vp.add_argument("--source-ref"); vp.add_argument("--gate-bundle", type=Path); vp.add_argument("--output", type=Path)
    br = commands.add_parser("build-row"); br.add_argument("--probe", type=Path, required=True); br.add_argument("--gate-bundle", type=Path); br.add_argument("--output", type=Path, required=True)
    asm = commands.add_parser("assemble-status"); asm.add_argument("--rows", type=Path, required=True); asm.add_argument("--runner-lifecycle", type=Path); asm.add_argument("--base", type=Path); asm.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "validate": return validate(args.source_ref, args.verify_provenance)
    if args.command == "verify-provenance": return verify_provenance_command(args.package, args.evidence, args.source_ref, args.gate_bundle, args.output)
    if args.command == "build-row": return build_row(args.probe, args.gate_bundle, args.output)
    return assemble_status(args.rows, args.runner_lifecycle, args.base, args.output)


if __name__ == "__main__": sys.exit(main())
