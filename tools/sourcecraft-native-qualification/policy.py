"""Protected policy validation for the independently installed authority."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from codec import Rejected, read_file
from contract import sha

PRIVATE_ROOT = Path("/private")
# macOS exposes /etc and /var as aliases; admit only their non-symlink target.
POLICY_PATH = PRIVATE_ROOT / "etc/gocode/sourcecraft-native-qualification/policy.json"
EVIDENCE_ROOT = PRIVATE_ROOT / "var/db/gocode/sourcecraft-native-qualification/evidence"
LEDGER_ROOT = PRIVATE_ROOT / "var/db/gocode/sourcecraft-native-qualification/replay"
RUNNE_REPOSITORY = "https://git@git.sourcecraft.dev/ryltsevmg/runne.git"
RUNNE_WORKFLOW = "desktop-qualification"
EVIDENCE_SIGNER = Path("/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-sign-evidence")
MODULES = frozenset({"codec.py","contract.py","controller.py","ed25519_verify.py","native_checks.py","package_subject.py","policy.py","process_control.py","profile_grants.py","signer.py","signer_broker.py","verifier.py"})
FIELDS = {"schema_version","policy_id","repository","workflow","job","protected_ref","source_revision","candidate_sha256","release_tuple_v3_sha256","candidate_root","package_root","controller","verifier","native_executor","attestation_verifier","evidence_signer","signer_broker","authority_modules","evidence_authority","writer_profile","test_only"}


def validate(value: object, verifier_path: Path, production: bool) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != FIELDS or value.get("schema_version") != "runne/sourcecraft-native-qualification-policy/v1" or value.get("policy_id") != "runne/writer-qualification/v1":
        _reject("protected policy is invalid")
    if value.get("repository") != RUNNE_REPOSITORY or value.get("workflow") != RUNNE_WORKFLOW or not _revision(value.get("source_revision")) or any(not sha(value.get(key)) for key in ("candidate_sha256", "release_tuple_v3_sha256")):
        _reject("protected source tuple is invalid")
    if any(not isinstance(value.get(key), str) or not value[key] for key in ("job", "protected_ref")) or not isinstance(value.get("test_only"), bool):
        _reject("protected workflow binding is invalid")
    _root(value.get("candidate_root"), "candidate root"); _root(value.get("package_root"), "package root")
    for key in ("controller", "verifier", "native_executor", "attestation_verifier", "evidence_signer", "signer_broker"):
        _identity(value.get(key), key.replace("_", " "), production)
    if Path(value["evidence_signer"]["path"]) != EVIDENCE_SIGNER:
        _reject("evidence signer is not the protected installation")
    if Path(value["verifier"]["path"]) != verifier_path:
        _reject("running verifier is not the protected installation")
    authority = value.get("evidence_authority")
    if not isinstance(authority, dict) or set(authority) != {"key_id", "public_key"}:
        _reject("evidence authority is invalid")
    try: public_key = bytes.fromhex(authority["public_key"])
    except (TypeError, ValueError): _reject("evidence authority is invalid")
    if len(public_key) != 32 or authority.get("key_id") != hashlib.sha256(public_key).hexdigest():
        _reject("evidence authority pin is invalid")
    if value.get("writer_profile") != {"attestation":2,"prelude":1,"ack":1}:
        _reject("writer profile pin is invalid")
    modules = value.get("authority_modules")
    if not isinstance(modules, dict) or set(modules) != MODULES:
        _reject("authority module pins are invalid")
    for name, identity in modules.items():
        _identity(identity, f"authority module {name}", False)
    if production and value["test_only"]:
        _reject("production verifier rejects test-only policy")
    return value


def verify_authority_modules(policy: dict[str, object]) -> None:
    """Rehash every privileged implementation module before authority effects."""
    modules = policy["authority_modules"]
    for name in MODULES:
        identity = modules[name]
        path = Path(identity["path"])
        if path.name != name:
            _reject("authority module digest differs")
        installed(path)
        if hashlib.sha256(read_file(path)).hexdigest() != identity["sha256"]:
            _reject("authority module digest differs")


def installed(path: Path, *, owner: int = 0, boundary: Path = Path("/")) -> None:
    """Require a root-owned, non-writable protected file or directory."""
    try:
        for item in (path, *path.parents):
            info = item.lstat()
            if item.is_symlink() or info.st_uid != owner or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH): _reject("protected installation permissions are invalid")
            if item == boundary: break
    except OSError:
        _reject("protected installation is unavailable")


def fixed_ledger(workflow_run_id: str, source_revision: str, policy_id: str) -> Path:
    if not workflow_run_id or not _revision(source_revision) or policy_id != "runne/writer-qualification/v1":
        _reject("replay identity is invalid")
    subject = policy_id + chr(0) + workflow_run_id
    return LEDGER_ROOT / f"{source_revision}-{hashlib.sha256(subject.encode()).hexdigest()}"


def _identity(value: object, kind: str, production: bool) -> None:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"} or not isinstance(value.get("path"), str) or not os.path.isabs(value["path"]) or not sha(value.get("sha256")):
        _reject(f"{kind} identity is invalid")
    path = Path(value["path"])
    if production:
        installed(path)
        if hashlib.sha256(read_file(path)).hexdigest() != value["sha256"]:
            _reject(f"{kind} digest differs from policy")


def _root(value: object, kind: str) -> None:
    if not isinstance(value, str) or not os.path.isabs(value) or Path(value).is_symlink():
        _reject(f"{kind} is invalid")


def _revision(value: object) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(char in "0123456789abcdef" for char in value)


def _reject(reason: str) -> None:
    raise Rejected(reason)
