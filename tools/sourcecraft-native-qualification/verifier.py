#!/usr/bin/python3 -I
"""Fail-closed installed verifier for macOS DPK qualification evidence."""
from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codec import Rejected, canonical, digest, entries, file_digest, inventory, load_installed_json, load_json, package_snapshot, parse_json, read_file
from contract import CANARY, ROLE_PATHS, sha, validate_row
from native_checks import verify_roles
from controller import STAGES, _attestation_receipt
from package_subject import canonical_roles, open_package, signed_subject, snapshot, subject
from ed25519_verify import verify
from policy import EVIDENCE_ROOT, LEDGER_ROOT, POLICY_PATH, fixed_ledger, installed, validate, verify_authority_modules
from process_control import run as run_protected

DOMAIN = b"runne/macos-xpc-service-qualification/v1\x00"
FILES = frozenset({"macos-13-arm64.json","expected-tuples.json","writer-transcript-v2.json","service-admission.json","sourcecraft-attestation.bundle","controller-lifecycle.json"})
NATIVE_TUPLE = ("launch_agent_plist_sha256","entitlements_sha256","provisioning_sha256","protocol_sha256","contract_sha256")
ROOT_FILES = FILES | {"artifact-manifest.json", "signed-envelope.json", "controller-conformance.json"}
ENVELOPE = {"schema_version","source_revision","workflow_run_id","namespace_sha256","signer_key_id","row_sha256","expected_tuples_sha256","artifact_manifest_sha256","conformance_sha256","writer_transcript_sha256","service_admission_sha256","controller_lifecycle_sha256","started_at","finished_at","cleanup_verified","signature"}
CONFORMANCE = {"schema_version","policy_id","candidate_sha256","release_tuple_v3_sha256","controller","writer_transcript_sha256","service_admission_sha256","controller_lifecycle_sha256","cleanup_verified","artifact_manifest_sha256"}


def verify_test_vector(policy: object, root: Path, now: datetime, verifier: Path,
                       attestation: object) -> dict[str, object]:
    """Non-authoritative test-vector API; production never calls this function."""
    return _verify(policy, root, now, verifier, attestation, production=False)


def verify_production() -> dict[str, object]:
    """Use only fixed runner-owned paths; no caller-selected policy or ledger exists."""
    installed(POLICY_PATH.parent); installed(POLICY_PATH); installed(LEDGER_ROOT)
    policy = load_installed_json(POLICY_PATH)
    verify_authority_modules(validate(policy, Path(sys.argv[0]), True))
    return _verify(policy, EVIDENCE_ROOT, datetime.now(timezone.utc), Path(sys.argv[0]),
                   EVIDENCE_ROOT / "sourcecraft-attestation.bundle", production=True)


def _verify(policy_value: object, root: Path, now: datetime, verifier: Path,
            attestation: object, production: bool) -> dict[str, object]:
    policy = validate(policy_value, verifier, production)
    _root(root, policy, production)
    row, tuples, manifest, envelope, conformance, transcript, service, lifecycle = _load(root)
    if production:
        for name in ROOT_FILES: installed(root / name)
    validate_row(row, tuples, policy)
    if row["runner"]["workflow_run_id"] != envelope["workflow_run_id"]:
        raise Rejected("row workflow identity differs from envelope")
    snapshot, package_subject, bundle = _manifest(manifest, root, row, tuples, Path(policy["package_root"]), production)
    if production: verify_roles(Path(policy["package_root"]), row["tuple"], row["code_identities"])
    _envelope(envelope, row, tuples, manifest, conformance, transcript, service, lifecycle, policy, now)
    _conformance(conformance, manifest, transcript, service, lifecycle, policy); _lifecycle(lifecycle, envelope, snapshot, package_subject, bundle, policy, manifest)
    _transcript(transcript, policy); _service(service)
    if transcript["workflow_run_id"] != envelope["workflow_run_id"] or service["workflow_run_id"] != envelope["workflow_run_id"] or transcript["tuple_sha256"] != row["tuple"]["tuple_sha256"] or service["tuple_sha256"] != row["tuple"]["tuple_sha256"]: raise Rejected("native receipts are not bound to the qualified row")
    _attestation(attestation, envelope, policy, production)
    if production: _consume(envelope, policy)
    return {"qualified":True,"policy_id":policy["policy_id"],"candidate_sha256":policy["candidate_sha256"],"release_tuple_v3_sha256":policy["release_tuple_v3_sha256"]}


def _root(root: Path, policy: dict[str, object], production: bool) -> None:
    if not root.is_absolute() or root.is_symlink() or (production and root != EVIDENCE_ROOT):
        raise Rejected("evidence root is not runner owned")
    if production: installed(root); installed(Path(policy["package_root"]))
    if root == Path(policy["candidate_root"]):
        raise Rejected("evidence root is candidate controlled")
    if entries(root) != ROOT_FILES:
        raise Rejected("evidence inventory is not exact")


def _load(root: Path) -> tuple[object, object, object, object, object, object, object, object]:
    return tuple(load_json(root / name) for name in ("macos-13-arm64.json","expected-tuples.json","artifact-manifest.json","signed-envelope.json","controller-conformance.json","writer-transcript-v2.json","service-admission.json","controller-lifecycle.json"))  # type: ignore[return-value]


def _manifest(value: object, root: Path, row: object, tuples: object, package: Path, production: bool) -> tuple[str, str, str]:
    if not isinstance(value, dict) or set(value) != {"schema_version","row_sha256","expected_tuples_sha256","native_measurements_sha256","files","package_files","role_paths","role_measurements"} or value.get("schema_version") != "runne/native-qualification-artifact-manifest/v1" or value.get("row_sha256") != digest(row) or value.get("expected_tuples_sha256") != digest(tuples) or not isinstance(row, dict) or value.get("native_measurements_sha256") != digest({name:row["tuple"][name] for name in NATIVE_TUPLE}):
        raise Rejected("artifact manifest is invalid")
    listed = value.get("files")
    if not isinstance(listed, list) or len(listed) != len(FILES): raise Rejected("artifact inventory is incomplete")
    mapped = {item.get("name"): item.get("sha256") for item in listed if isinstance(item, dict) and set(item) == {"name","sha256"}}
    if set(mapped) != FILES or any(not sha(value) for value in mapped.values()): raise Rejected("artifact inventory is invalid")
    for name in FILES:
        if mapped[name] != __import__("hashlib").sha256(read_file(root / name)).hexdigest():
            raise Rejected("artifact inventory digest differs")
    packages = value.get("package_files")
    if not isinstance(packages, list) or not packages: raise Rejected("package inventory is incomplete")
    names = set(); expected = {}
    for item in packages:
        if not isinstance(item, dict) or set(item) != {"name","sha256"} or not isinstance(item.get("name"), str) or not sha(item.get("sha256")) or item["name"].startswith("/") or any(part in {"", ".", ".."} for part in Path(item["name"]).parts): raise Rejected("package inventory is invalid")
        names.add(item["name"]); expected[item["name"]] = item["sha256"]
    if len(names) != len(packages): raise Rejected("package inventory is invalid")
    descriptor = open_package(str(package))
    try: observed = subject(descriptor, production)
    finally: os.close(descriptor)
    actual = snapshot(observed)
    if len(expected) != len(actual) or expected != actual: raise Rejected("package inventory is not exact")
    role_paths = value.get("role_paths")
    if role_paths != ROLE_PATHS: raise Rejected("package role paths are invalid")
    for role, name in role_paths.items():
        if not isinstance(name, str) or actual.get(name) != row["tuple"][f"{role}_sha256"]: raise Rejected("package role identity differs")
    measured = canonical_roles(observed)
    if value.get("role_measurements") != measured:
        raise Rejected("package role measurements differ")
    if row["artifact_scan"]["files_scanned"] != len(actual) + len(FILES): raise Rejected("artifact scan count differs")
    if row["artifact_scan"]["scan_subject_sha256"] != digest({"package_files":actual,"role_measurements":measured,"canary":CANARY}):
        raise Rejected("artifact scan subject differs")
    return digest(actual), digest(signed_subject(observed)), file_digest(root / "sourcecraft-attestation.bundle")


def _envelope(value: object, row: object, tuples: object, manifest: object, conformance: object,
              transcript: object, service: object, lifecycle: object, policy: dict[str, object], now: datetime) -> None:
    if not isinstance(value, dict) or set(value) != ENVELOPE or value.get("schema_version") != "macos-xpc-service-signed-envelope.v1": raise Rejected("signed envelope is invalid")
    if value.get("source_revision") != policy["source_revision"] or not _run(value.get("workflow_run_id")) or any(not sha(value.get(name)) for name in ("namespace_sha256","signer_key_id","row_sha256","expected_tuples_sha256","artifact_manifest_sha256","conformance_sha256","writer_transcript_sha256","service_admission_sha256","controller_lifecycle_sha256")):
        raise Rejected("signed envelope metadata is invalid")
    bindings = {"row_sha256":digest(row),"expected_tuples_sha256":digest(tuples),"artifact_manifest_sha256":digest(manifest),"conformance_sha256":digest(conformance),"writer_transcript_sha256":digest(transcript),"service_admission_sha256":digest(service),"controller_lifecycle_sha256":digest(lifecycle)}
    if any(value.get(name) != expected for name, expected in bindings.items()) or value.get("cleanup_verified") is not True or value.get("signer_key_id") != policy["evidence_authority"]["key_id"]:
        raise Rejected("signed envelope subject is invalid")
    _fresh(value, now)
    signature = value.get("signature")
    if not isinstance(signature, dict) or set(signature) != {"algorithm","value"} or signature.get("algorithm") != "ed25519": raise Rejected("signature is invalid")
    try:
        raw = base64.b64decode(signature["value"], altchars=b"-_", validate=True); key = bytes.fromhex(policy["evidence_authority"]["public_key"])
    except (TypeError, ValueError): raise Rejected("signature is invalid") from None
    if base64.urlsafe_b64encode(raw).decode("ascii") != signature.get("value") or len(raw) != 64 or not verify(key, DOMAIN + canonical({name:item for name,item in value.items() if name != "signature"}), raw):
        raise Rejected("signature is invalid")


def _fresh(value: dict[str, object], now: datetime) -> None:
    parsed = []
    for name in ("started_at","finished_at"):
        try: parsed.append(datetime.strptime(value[name], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc))
        except (KeyError, TypeError, ValueError): raise Rejected("envelope timestamps are invalid") from None
    if not parsed[0] <= parsed[1] <= now or parsed[1] - parsed[0] > timedelta(hours=2) or now - parsed[0] > timedelta(hours=24): raise Rejected("envelope is stale")


def _conformance(value: object, manifest: object, transcript: object, service: object, lifecycle: object, policy: dict[str, object]) -> None:
    if not isinstance(value, dict) or set(value) != CONFORMANCE or value.get("schema_version") != "runne/native-qualification-conformance/v1": raise Rejected("conformance receipt is invalid")
    expected = {"policy_id":policy["policy_id"],"candidate_sha256":policy["candidate_sha256"],"release_tuple_v3_sha256":policy["release_tuple_v3_sha256"],"controller":policy["controller"],"artifact_manifest_sha256":digest(manifest),"writer_transcript_sha256":digest(transcript),"service_admission_sha256":digest(service),"controller_lifecycle_sha256":digest(lifecycle),"cleanup_verified":True}
    if any(value.get(name) != item for name,item in expected.items()): raise Rejected("conformance receipt is incomplete")


def _lifecycle(value: object, envelope: dict[str, object], snapshot: str,
               package_subject: str, bundle: str, policy: dict[str, object],
               manifest: object) -> None:
    fields = {"schema_version","order","workflow_run_id","request_sha256","package_snapshot_sha256","package_subject_sha256","attestation_sha256","attestation_receipt_sha256","preflight_sha256","result_sha256","outcome"}
    if not isinstance(value, dict) or not isinstance(manifest, dict) or set(value) != fields or value.get("schema_version") != "runne/native-dpk-controller-lifecycle/v1" or value.get("order") != ["request","preflight","execute","complete"] or value.get("workflow_run_id") != envelope["workflow_run_id"] or value.get("outcome") != "cleanup_verified" or value.get("package_snapshot_sha256") != snapshot or value.get("package_subject_sha256") != package_subject or value.get("attestation_sha256") != bundle or any(not sha(value.get(name)) for name in fields - {"schema_version","order","workflow_run_id","outcome"}):
        raise Rejected("controller lifecycle is invalid")
    receipt = _attestation_receipt(policy, envelope["workflow_run_id"], snapshot, package_subject, bundle)
    request = {"schema_version":"runne/native-dpk-controller-request/v1",
               **{name:policy[name] for name in ("repository","workflow","job","protected_ref","source_revision","candidate_sha256","release_tuple_v3_sha256")},
               "package_snapshot_sha256":snapshot,"package_subject_sha256":package_subject,
               "attestation_sha256":bundle,"attestation_receipt_sha256":digest(receipt),
               "deployment_sha256":digest(__import__("contract").DEPLOYMENT),"role_paths":ROLE_PATHS,
               "role_measurements":manifest.get("role_measurements"),"workflow_run_id":envelope["workflow_run_id"],
               "selectors":sorted(__import__("contract").SELECTORS),"stages":list(STAGES),
               "executor_sha256":policy["native_executor"]["sha256"]}
    preflight = {"schema_version":"runne/native-dpk-preflight-result/v1","request_sha256":digest(request),
                 "package_snapshot_sha256":snapshot,"package_subject_sha256":package_subject,
                 "developer_id_verified":True,"notarized":True,"provisioning_verified":True,
                 "role_paths":ROLE_PATHS,"role_measurements":manifest.get("role_measurements"),
                 "deployment_sha256":digest(__import__("contract").DEPLOYMENT),"attestation_sha256":bundle,
                 "attestation_receipt_sha256":digest(receipt)}
    terminal = {"schema_version":"runne/native-dpk-controller-result/v1","workflow_run_id":envelope["workflow_run_id"],
                "request_sha256":digest(request),"package_snapshot_sha256":snapshot,
                "package_subject_sha256":package_subject,"evidence_ready":True,"cleanup_verified":True}
    expected = {"request_sha256":digest(request),"attestation_receipt_sha256":digest(receipt),
                "preflight_sha256":digest(preflight),"result_sha256":digest(terminal)}
    if any(value[name] != item for name, item in expected.items()):
        raise Rejected("controller lifecycle receipts differ")


def _transcript(value: object, policy: dict[str, object]) -> None:
    if not isinstance(value, dict) or set(value) != {"schema_version","role","profile","attestation","prelude","ack","status","workflow_run_id","tuple_sha256","attestation_receipt","prelude_receipt","ack_receipt","attestation_sha256","prelude_sha256","ack_sha256"}: raise Rejected("writer qualification transcript is invalid")
    expected = {"schema_version":"runne/writer-qualified-transcript/v2","role":"writer","profile":policy["policy_id"],"attestation":2,"prelude":1,"ack":1,"status":"verified"}
    if any(value.get(name) != item for name,item in expected.items()) or not _run(value.get("workflow_run_id")) or not sha(value.get("tuple_sha256")): raise Rejected("writer qualification transcript is invalid")
    receipts = {"attestation":{"profile":2,"status":"verified"},"prelude":{"version":1,"status":"verified"},"ack":{"version":1,"status":"verified"}}
    if any(value.get(f"{name}_receipt") != receipt or value.get(f"{name}_sha256") != digest(receipt) for name,receipt in receipts.items()): raise Rejected("writer semantic transcript is invalid")


def _service(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"schema_version","source_role","target_role","direct_admission","ordinary_writer_v1","workflow_run_id","tuple_sha256","admission_receipt","endpoint_receipt","admission_sha256","endpoint_sha256"}: raise Rejected("service admission evidence is invalid")
    expected = {"schema_version":"runne/service-direct-admission/v1","source_role":"daemon","target_role":"credential-service","direct_admission":"verified","ordinary_writer_v1":"role_routing_only"}
    if any(value.get(name) != item for name,item in expected.items()) or not _run(value.get("workflow_run_id")) or not sha(value.get("tuple_sha256")): raise Rejected("service admission evidence is invalid")
    receipts = {"admission":{"source_role":"daemon","status":"verified","target_role":"credential-service"},"endpoint":{"endpoint":f"{__import__('contract').SERVICE}.writer.v1","status":"verified"}}
    if any(value.get(f"{name}_receipt") != receipt or value.get(f"{name}_sha256") != digest(receipt) for name,receipt in receipts.items()): raise Rejected("service semantic receipt is invalid")


def _attestation(value: object, envelope: dict[str, object], policy: dict[str, object], production: bool) -> None:
    if not production:
        if value == {"test_only":True,"workflow_run_id":envelope["workflow_run_id"]}: return
        raise Rejected("test vector attestation is invalid")
    if not isinstance(value, Path): raise Rejected("external attestation is invalid")
    identity = policy["attestation_verifier"]
    try:
        snapshot, package_subject, bundle = _package_bindings(policy, envelope, value)
        output, result = run_protected([identity["path"],"--bundle",str(value),"--repository",policy["repository"],"--workflow",policy["workflow"],"--job",policy["job"],"--ref",policy["protected_ref"],"--source-revision",envelope["source_revision"],"--run",envelope["workflow_run_id"],"--package-snapshot",snapshot,"--package-subject",package_subject], None, contain=True)
        report = parse_json(output)
    except Rejected: raise Rejected("external attestation rejected") from None
    expected = _attestation_receipt(policy, envelope["workflow_run_id"], snapshot, package_subject, bundle)
    if result != 0 or report != expected: raise Rejected("external attestation rejected")


def _package_bindings(policy: dict[str, object], envelope: dict[str, object], bundle_path: Path) -> tuple[str, str, str]:
    descriptor = open_package(str(policy["package_root"]))
    try: measured = subject(descriptor, True)
    finally: os.close(descriptor)
    return digest(snapshot(measured)), digest(signed_subject(measured)), file_digest(bundle_path)


def _consume(envelope: dict[str, object], policy: dict[str, object]) -> None:
    path = fixed_ledger(envelope["workflow_run_id"], envelope["source_revision"], policy["policy_id"])
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError: raise Rejected("signed run was already consumed") from None
    except OSError: raise Rejected("runner replay ledger is unavailable") from None
    try:
        payload = canonical({"workflow_run_id":envelope["workflow_run_id"],"source_revision":envelope["source_revision"],"policy_id":policy["policy_id"]})
        if os.write(descriptor, payload) != len(payload): raise Rejected("runner replay ledger is unavailable")
        os.fsync(descriptor)
    finally: os.close(descriptor)
    try:
        parent = os.open(LEDGER_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
    except OSError: raise Rejected("runner replay ledger is unavailable") from None


def _run(value: object) -> bool:
    return isinstance(value, str) and value.replace("_", "a").replace("-", "a").isalnum() and 1 <= len(value) <= 128


def main(argv: list[str] | None = None) -> int:
    if argv not in (None, []):
        print('{"qualified":false,"reason":"external_conformance_rejected"}'); return 1
    try: verdict = verify_production()
    except (Rejected, ValueError): verdict = {"qualified":False,"reason":"external_conformance_rejected"}
    print(json.dumps(verdict, sort_keys=True, separators=(",", ":")))
    return 0 if verdict["qualified"] else 1


if __name__ == "__main__": raise SystemExit(main())
