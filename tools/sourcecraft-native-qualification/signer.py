#!/usr/bin/python3 -I
"""Runner-owned issuer for the completed native qualification lifecycle."""
from __future__ import annotations

import base64
import hashlib
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from codec import Rejected, canonical, digest, entries, file_digest, load_installed_json, load_json
from contract import ROLE_PATHS, validate_row
from controller import _attestation_receipt
from ed25519_verify import sign
from native_checks import verify_roles
from package_subject import canonical_roles, open_package, signed_subject, snapshot, subject
from policy import EVIDENCE_ROOT, POLICY_PATH, installed, validate, verify_authority_modules
from verifier import DOMAIN, FILES, ROOT_FILES, _conformance, _lifecycle, _service, _transcript

KEY_PATH = Path("/private/var/db/gocode/sourcecraft-native-qualification/evidence-authority-ed25519.seed")
UNSIGNED_FILES = ROOT_FILES - {"signed-envelope.json"}


def issue(policy_value: object, root: Path, key_path: Path, *, production: bool = True, authorized: bool = False) -> dict[str, object]:
    """Sign fixed runner-owned evidence only after the controller terminal receipt."""
    policy = validate(policy_value, Path(policy_value["verifier"]["path"]), production)
    if production: verify_authority_modules(policy)
    if production and (not authorized or os.geteuid() != 0):
        raise Rejected("signer is not runner owned")
    if entries(root) != UNSIGNED_FILES or root.is_symlink(): raise Rejected("unsigned evidence inventory is not exact")
    if production:
        for path in (root, key_path, *[root / name for name in UNSIGNED_FILES]): installed(path)
    row, tuples, manifest, conformance, transcript, service, lifecycle = (load_json(root / name) for name in ("macos-13-arm64.json", "expected-tuples.json", "artifact-manifest.json", "controller-conformance.json", "writer-transcript-v2.json", "service-admission.json", "controller-lifecycle.json"))
    validate_row(row, tuples, policy)
    package = Path(policy["package_root"]); descriptor = open_package(str(package))
    try: measured = subject(descriptor, production)
    finally: os.close(descriptor)
    actual = snapshot(measured); roles = canonical_roles(measured); bundle = file_digest(root / "sourcecraft-attestation.bundle")
    listed = manifest.get("package_files") if isinstance(manifest, dict) else None
    expected = {item.get("name"): item.get("sha256") for item in listed if isinstance(item, dict)} if isinstance(listed, list) else {}
    if not isinstance(manifest, dict) or len(expected) != len(listed) or expected != actual or manifest.get("role_paths") != ROLE_PATHS or manifest.get("role_measurements") != roles:
        raise Rejected("package-bound manifest differs")
    run = row["runner"]["workflow_run_id"] if isinstance(row, dict) and isinstance(row.get("runner"), dict) else None
    envelope = {"workflow_run_id":run, "source_revision":policy["source_revision"]}
    _conformance(conformance, manifest, transcript, service, lifecycle, policy)
    _lifecycle(lifecycle, envelope, digest(actual), digest(signed_subject(measured)), bundle, policy, manifest)
    _transcript(transcript, policy); _service(service)
    if not isinstance(run, str) or transcript["workflow_run_id"] != run or service["workflow_run_id"] != run:
        raise Rejected("issuance receipts are not one lifecycle")
    if production: verify_roles(package, row["tuple"])
    receipt = _attestation_receipt(policy, run, digest(actual), digest(signed_subject(measured)), bundle)
    if lifecycle["attestation_receipt_sha256"] != digest(receipt): raise Rejected("package attestation differs")
    seed = _seed(key_path, policy, production)
    now = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    unsigned = {"schema_version":"macos-xpc-service-signed-envelope.v1", "source_revision":policy["source_revision"], "workflow_run_id":run, "namespace_sha256":digest({"policy_id":policy["policy_id"],"workflow_run_id":run,"tuple_sha256":row["tuple"]["tuple_sha256"]}), "signer_key_id":policy["evidence_authority"]["key_id"], "row_sha256":digest(row), "expected_tuples_sha256":digest(tuples), "artifact_manifest_sha256":digest(manifest), "conformance_sha256":digest(conformance), "writer_transcript_sha256":digest(transcript), "service_admission_sha256":digest(service), "controller_lifecycle_sha256":digest(lifecycle), "started_at":now, "finished_at":now, "cleanup_verified":True}
    _, signature = sign(seed, DOMAIN + canonical(unsigned)); unsigned["signature"] = {"algorithm":"ed25519", "value":base64.urlsafe_b64encode(signature).decode("ascii")}
    _write(root / "signed-envelope.json", canonical(unsigned)); return unsigned


def _seed(path: Path, policy: dict[str, object], production: bool) -> bytes:
    if production: installed(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077 or stat.S_IMODE(info.st_mode) not in {0o400, 0o600} or (production and info.st_uid != 0): raise Rejected("evidence key permissions are invalid")
            seed = os.read(descriptor, 33)
            if os.read(descriptor, 1): raise Rejected("evidence key is invalid")
        finally: os.close(descriptor)
    except OSError: raise Rejected("evidence key is unavailable") from None
    public, _ = sign(seed, b"")
    if hashlib.sha256(public).hexdigest() != policy["evidence_authority"]["key_id"] or public.hex() != policy["evidence_authority"]["public_key"]:
        raise Rejected("evidence key does not match policy")
    return seed


def _write(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(descriptor, payload) != len(payload): raise Rejected("signed evidence write failed")
            os.fsync(descriptor)
        finally: os.close(descriptor)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
    except OSError: raise Rejected("signed evidence write failed") from None


def main(argv: list[str] | None = None) -> int:
    return 1


if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
