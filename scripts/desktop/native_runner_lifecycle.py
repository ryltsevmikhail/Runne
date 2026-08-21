#!/usr/bin/env python3
"""Verify independent, signed native-runner destruction/reimage evidence."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile

BLOCKER = "RUNNER_TRUST_UNVERIFIED"
MAX_WAIT_SECONDS = 60
MAX_ADMISSION_TTL = timedelta(hours=4)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load_json(path: Path) -> object:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def _sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _expected_completion(rows: list[dict[str, object]]) -> dict[str, tuple[str, str, str, str, str, datetime, datetime]] | None:
    expected: dict[str, tuple[str, str, str, str, str, datetime, datetime]] = {}
    for row in rows:
        runner = row.get("runner")
        if not isinstance(runner, dict):
            return None
        fields = tuple(runner.get(key) for key in ("instance_id", "image_sha256", "boot_measurement_sha256", "job_id", "workflow_run_id", "admission_sha256", "admission_issued_at", "admission_expires_at"))
        if not isinstance(fields[0], str) or not all(_sha256(value) for value in fields[1:3]) or not all(isinstance(value, str) and value for value in fields[3:]):
            return None
        try: issued, expires = (datetime.fromisoformat(fields[index].replace("Z", "+00:00")) for index in (6, 7))
        except ValueError: return None
        if expires - issued > MAX_ADMISSION_TTL or fields[0] in expected:
            return None
        expected[fields[0]] = (fields[1], fields[2], fields[3], fields[4], fields[5], issued, expires)
    return expected or None


def verify_completion_attestation(attestation: object, trust_root: str, trust_root_sha256: str, rows: list[dict[str, object]], now: datetime | None = None) -> list[str]:
    """Validate a public-key signed control-plane statement against runner facts."""
    expected = _expected_completion(rows)
    if not trust_root or expected is None or not isinstance(attestation, dict):
        return [BLOCKER]
    completion = attestation.get("completion")
    if not _verify_public_signature(attestation, trust_root, trust_root_sha256) or attestation.get("schema_version") != "desktop-native-runner-lifecycle.v1" or not isinstance(completion, list):
        return [BLOCKER]
    actual: dict[str, tuple[str, str, str, str, str, datetime, datetime]] = {}
    for fact in completion:
        if not isinstance(fact, dict) or fact.get("action") not in {"destroyed", "reimaged"} or not isinstance(fact.get("completed_at"), str):
            return [BLOCKER]
        if not isinstance(fact.get("job_completed_at"), str): return [BLOCKER]
        try:
            completed = datetime.fromisoformat(fact["completed_at"].replace("Z", "+00:00"))
            job_completed = datetime.fromisoformat(fact["job_completed_at"].replace("Z", "+00:00"))
        except ValueError: return [BLOCKER]
        now = now or datetime.now(UTC)
        if completed < now - timedelta(days=7) or completed > now: return [BLOCKER]
        fields = tuple(fact.get(key) for key in ("instance_id", "image_sha256", "boot_measurement_sha256", "job_id", "workflow_run_id", "admission_sha256"))
        if not isinstance(fields[0], str) or not all(_sha256(value) for value in fields[1:3]) or not all(isinstance(value, str) for value in fields[3:5]) or not _sha256(fields[5]) or fields[0] in actual:
            return [BLOCKER]
        if fields[0] not in expected or not expected[fields[0]][5] <= job_completed <= completed <= min(now, expected[fields[0]][6]):
            return [BLOCKER]
        actual[fields[0]] = (fields[1], fields[2], fields[3], fields[4], fields[5], expected[fields[0]][5], expected[fields[0]][6])
    return [] if actual == expected else [BLOCKER]


def _collect_rows(rows_dir: Path) -> list[dict[str, object]]:
    if not rows_dir.is_dir():
        return []
    rows: list[dict[str, object]] = []
    for path in sorted(rows_dir.rglob("native-platform-row.json")):
        value = load_json(path)
        if not isinstance(value, dict):
            raise ValueError("row is not an object")
        rows.append(value)
    return rows


def _request_completion(url: str, rows: list[dict[str, object]], wait_seconds: int, oidc_token_file: Path | None) -> object | None:
    try:
        token = oidc_token_file.read_text(encoding="utf-8").strip() if oidc_token_file else ""
        if not token: return None
        request = urllib.request.Request(url, data=canonical({"rows": rows}), headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, method="POST")
        with urllib.request.urlopen(request, timeout=wait_seconds) as response:
            return json.loads(response.read().decode()) if response.status == 200 else None
    except (OSError, ValueError):
        return None


def _pinned_rsa_copy(trust_root: str, trust_root_sha256: str, directory: Path) -> Path | None:
    if not _sha256(trust_root_sha256): return None
    try:
        root_bytes = Path(trust_root).read_bytes()
        if hashlib.sha256(root_bytes).hexdigest() != trust_root_sha256: return None
        root = directory / "pinned-public-root.pem"; root.write_bytes(root_bytes); root.chmod(0o600)
        rsa = subprocess.run(["openssl", "rsa", "-pubin", "-in", str(root), "-noout"], check=False, capture_output=True)
        result = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(root), "-text", "-noout"], check=False, capture_output=True, text=True)
        match = re.search(r"Public-Key: \((\d+) bit\)", result.stdout)
        return root if rsa.returncode == 0 and result.returncode == 0 and match is not None and int(match.group(1)) >= 3072 else None
    except (OSError, subprocess.SubprocessError): return None


def _verify_public_signature(value: object, trust_root: str, trust_root_sha256: str) -> bool:
    if not isinstance(value, dict) or value.get("signature_algorithm") != "RSA-SHA256" or not isinstance(value.get("signature"), str):
        return False
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    try:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); root = _pinned_rsa_copy(trust_root, trust_root_sha256, directory)
            if root is None: return False
            payload, signature = directory / "payload", directory / "signature"
            payload.write_bytes(canonical(unsigned)); signature.write_bytes(base64.b64decode(value["signature"], validate=True))
            return subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(root), "-signature", str(signature), str(payload)], check=False, capture_output=True).returncode == 0
    except (OSError, ValueError, subprocess.SubprocessError): return False


def verify_admission_identity(identity: object, trust_root: str | None, trust_root_sha256: str | None, platform: str, job_id: str, workflow_run_id: str) -> bool:
    if not isinstance(identity, dict) or set(identity) != {"schema_version", "verified", "platform_id", "job_id", "workflow_run_id", "admission", "admission_sha256", "trust_root_sha256"} or identity.get("schema_version") != "desktop-native-runner-identity.v1" or identity.get("verified") is not True or identity.get("platform_id") != platform or identity.get("job_id") != job_id or identity.get("workflow_run_id") != workflow_run_id or identity.get("trust_root_sha256") != trust_root_sha256:
        return False
    request = identity.get("admission")
    required = ("instance_id", "image_sha256", "boot_measurement_sha256", "issued_at", "expires_at")
    valid = isinstance(request, dict) and request.get("schema_version") == "desktop-native-runner-admission.v1" and request.get("platform_id") == platform and request.get("job_id") == job_id and request.get("workflow_run_id") == workflow_run_id and all(isinstance(request.get(key), str) and request[key] for key in required) and isinstance(identity.get("admission_sha256"), str) and identity["admission_sha256"] == hashlib.sha256(canonical(request)).hexdigest() and _verify_public_signature(request, trust_root or "", trust_root_sha256 or "")
    if not valid: return False
    try:
        now = datetime.now(UTC); issued = datetime.fromisoformat(request["issued_at"].replace("Z", "+00:00")); expires = datetime.fromisoformat(request["expires_at"].replace("Z", "+00:00"))
        return issued <= now < expires and expires - issued <= MAX_ADMISSION_TTL and _sha256(request["image_sha256"]) and _sha256(request["boot_measurement_sha256"])
    except ValueError: return False


def verify_admission(control_plane_url: str | None, trust_root: str | None, trust_root_sha256: str | None, oidc_token_file: Path | None, platform: str, job_id: str, workflow_run_id: str, output: Path, wait_seconds: int = MAX_WAIT_SECONDS) -> int:
    request = _request_completion(control_plane_url, [{"platform_id": platform, "runner": {"job_id": job_id, "workflow_run_id": workflow_run_id}}], wait_seconds, oidc_token_file) if control_plane_url else None
    result = {"schema_version": "desktop-native-runner-identity.v1", "verified": True, "platform_id": platform, "job_id": job_id, "workflow_run_id": workflow_run_id, "admission": request, "admission_sha256": hashlib.sha256(canonical(request)).hexdigest() if isinstance(request, dict) else None, "trust_root_sha256": trust_root_sha256}
    valid = verify_admission_identity(result, trust_root, trust_root_sha256, platform, job_id, workflow_run_id)
    result["verified"] = valid
    if not valid: result["admission"] = result["admission_sha256"] = None
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"); return 0


def verify_completion(rows_dir: Path, control_plane_url: str | None, trust_root: str | None, trust_root_sha256: str | None, oidc_token_file: Path | None, output: Path, wait_seconds: int = MAX_WAIT_SECONDS) -> int:
    try:
        rows = _collect_rows(rows_dir)
    except (OSError, ValueError) as error:
        rows, detail = [], f"invalid runner row: {error}"
    else:
        detail = "control-plane URL/trust root absent; lifecycle proof unavailable"
    attestation = _request_completion(control_plane_url, rows, wait_seconds, oidc_token_file) if control_plane_url and trust_root and rows else None
    errors = verify_completion_attestation(attestation, trust_root or "", trust_root_sha256 or "", rows) if attestation else [BLOCKER]
    result = {"schema_version": "desktop-native-runner-lifecycle.v1", "verified": not errors,
              "disposition": "verified" if not errors else "blocked", "blocker_code": None if not errors else BLOCKER,
              "platforms": sorted(str(row.get("platform_id")) for row in rows), "rows": rows, "detail": detail if errors else "independent lifecycle completion verified"}
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify-completion", "verify-admission"))
    parser.add_argument("--rows", type=Path)
    parser.add_argument("--control-plane-url")
    parser.add_argument("--trust-root")
    parser.add_argument("--trust-root-sha256")
    parser.add_argument("--oidc-token-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform-pair")
    parser.add_argument("--job-id")
    parser.add_argument("--workflow-run-id")
    args = parser.parse_args(argv)
    if args.command == "verify-admission": return verify_admission(args.control_plane_url, args.trust_root, args.trust_root_sha256, args.oidc_token_file, args.platform_pair or "", args.job_id or "", args.workflow_run_id or "", args.output)
    return verify_completion(args.rows or Path("."), args.control_plane_url, args.trust_root, args.trust_root_sha256, args.oidc_token_file, args.output)


if __name__ == "__main__":
    sys.exit(main())
