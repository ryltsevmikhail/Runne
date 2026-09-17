#!/usr/bin/python3 -I
"""Fail-closed orchestration adapter for the separately installed native executor."""
from __future__ import annotations

import json
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from codec import Rejected, canonical, digest, file_digest, load_installed_json, parse_json
from contract import DEPLOYMENT, ROLE_PATHS, SELECTORS, sha
from policy import EVIDENCE_ROOT, POLICY_PATH, installed, validate, verify_authority_modules
from package_subject import canonical_roles, open_package, signed_subject, snapshot, subject
from process_control import run as run_protected

EXECUTOR = Path("/opt/gocode/sourcecraft/bin/runne-native-dpk-executor")
STAGES = ("install_exact_package","open_isolated_user","issue_case_ticket","observe_signal","terminal_readback","exact_locator_cleanup","scan_exports","emit_signed_evidence")


def validate_request(value: object) -> dict[str, object]:
    fields = {"schema_version","repository","workflow","job","protected_ref","source_revision","candidate_sha256","release_tuple_v3_sha256","package_snapshot_sha256","package_subject_sha256","attestation_sha256","attestation_receipt_sha256","deployment_sha256","role_paths","role_measurements","workflow_run_id","selectors","stages","executor_sha256"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != "runne/native-dpk-controller-request/v1": raise Rejected("controller request is invalid")
    selectors = value.get("selectors")
    hashes = ("candidate_sha256","release_tuple_v3_sha256","package_snapshot_sha256","package_subject_sha256","attestation_sha256","attestation_receipt_sha256","deployment_sha256","executor_sha256")
    if any(not sha(value.get(name)) for name in hashes) or not valid_run(value.get("workflow_run_id")) or not isinstance(selectors, list) or len(selectors) != len(SELECTORS) or set(selectors) != SELECTORS or value.get("stages") != list(STAGES) or value.get("role_paths") != ROLE_PATHS or not isinstance(value.get("role_measurements"), dict): raise Rejected("controller request is incomplete")
    return value


def handoff(request: object, policy: object, *, production: bool = True,
            executor: Path = EXECUTOR, evidence_root: Path | None = None) -> dict[str, object]:
    """Admit the fixed native executor; never synthesize a native success."""
    value = validate_request(request)
    verifier = Path("/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-verifier") if production else Path(checked_path(policy, "verifier"))
    checked = validate(policy, verifier, production)
    if production: verify_authority_modules(checked)
    package = Path(checked["package_root"]); descriptor: int | None = None
    try:
        if production: installed(package)
        descriptor = open_package(str(package)); before = subject(descriptor, production)
    except Rejected:
        return {"native_execution":False,"qualified":False,"reason":"package_not_protected"}
    before_digest = digest(snapshot(before)); subject_digest = digest(signed_subject(before))
    bindings = {name:checked[name] for name in ("repository","workflow","job","protected_ref","source_revision","candidate_sha256","release_tuple_v3_sha256")}
    bindings.update(package_snapshot_sha256=before_digest, package_subject_sha256=subject_digest,
                    executor_sha256=checked["native_executor"]["sha256"], deployment_sha256=digest(DEPLOYMENT))
    if value.get("role_measurements") != canonical_roles(before) or any(value.get(name) != expected for name,expected in bindings.items()):
        os.close(descriptor); return {"native_execution":False,"qualified":False,"reason":"request_differs_from_protected_policy"}
    try:
        if production: installed(executor)
        if Path(checked["native_executor"]["path"]) != executor or hashlib.sha256(executor.read_bytes()).hexdigest() != value["executor_sha256"]: raise Rejected("native executor digest differs")
    except (OSError, Rejected):
        os.close(descriptor)
        return {"native_execution":False,"qualified":False,"reason":"native_executor_unavailable"}
    try:
        assert descriptor is not None
        receipt = _pre_attestation(checked, value, production)
        if value["attestation_receipt_sha256"] != digest(receipt): raise Rejected("pre-native attestation differs")
        command = [str(executor), f"--package-fd={descriptor}"]
        preflight_output, preflight_status = run_protected(command + ["--preflight"], canonical(value), pass_fds=(descriptor,), contain=production)
        preflight = parse_json(preflight_output)
        expected_preflight = {"schema_version":"runne/native-dpk-preflight-result/v1",
                              "request_sha256":digest(value),"package_snapshot_sha256":before_digest,"package_subject_sha256":subject_digest,
                              "developer_id_verified":True,"notarized":True,"provisioning_verified":True,
                              "role_paths":ROLE_PATHS,"role_measurements":canonical_roles(before),"deployment_sha256":digest(DEPLOYMENT),
                              "attestation_sha256":value["attestation_sha256"],"attestation_receipt_sha256":digest(receipt)}
        if preflight_status != 0 or not isinstance(preflight, dict) or any(
            type(preflight.get(name)) is not bool
            for name in ("developer_id_verified", "notarized", "provisioning_verified")
        ) or canonical(preflight) != canonical(expected_preflight): raise Rejected("native preflight rejected")
        expected = {"schema_version":"runne/native-dpk-controller-result/v1",
                    "workflow_run_id":value["workflow_run_id"],
                    "request_sha256":digest(value), "package_snapshot_sha256":before_digest,"package_subject_sha256":subject_digest,
                    "evidence_ready":True, "cleanup_verified":True}
        output, status = run_protected(command + ["--execute"], canonical(value), pass_fds=(descriptor,), contain=production)
        terminal = parse_json(output)
        after = subject(descriptor, production)
        if status != 0 or not isinstance(terminal, dict) or any(
            type(terminal.get(name)) is not bool
            for name in ("evidence_ready", "cleanup_verified")
        ) or canonical(terminal) != canonical(expected) or after != before:
            raise Rejected("native executor terminal result rejected")
        lifecycle = {"schema_version":"runne/native-dpk-controller-lifecycle/v1","order":["request","preflight","execute","complete"],"workflow_run_id":value["workflow_run_id"],
                     "request_sha256":digest(value),"package_snapshot_sha256":before_digest,"package_subject_sha256":subject_digest,
                     "attestation_sha256":value["attestation_sha256"],"attestation_receipt_sha256":digest(receipt),"preflight_sha256":digest(preflight),
                     "result_sha256":digest(terminal),"outcome":"cleanup_verified"}
        if evidence_root is not None or production: _write_lifecycle(evidence_root or EVIDENCE_ROOT, lifecycle)
    except Rejected:
        return {"native_execution":False,"qualified":False,"reason":"native_executor_rejected"}
    finally:
        if descriptor is not None: os.close(descriptor)
    return {"native_execution":True,"evidence_ready":True,"qualified":False,"package_snapshot_sha256":before_digest}


def checked_path(policy: object, name: str) -> str:
    if not isinstance(policy, dict) or not isinstance(policy.get(name), dict) or not isinstance(policy[name].get("path"), str):
        raise Rejected("controller policy identity rejected")
    return policy[name]["path"]


def build_request(policy: dict[str, object], environment: dict[str, str]) -> dict[str, object]:
    expected_environment = {"SOURCECRAFT_REPO_URL":"repository","SOURCECRAFT_WORKFLOW":"workflow",
                            "SOURCECRAFT_TASK":"job","SOURCECRAFT_COMMIT_REF":"protected_ref",
                            "SOURCECRAFT_COMMIT_SHA":"source_revision"}
    if any(environment.get(env) != policy.get(field) for env,field in expected_environment.items()):
        raise Rejected("current protected run differs from policy")
    run = environment.get("SOURCECRAFT_RUN_ID")
    if not valid_run(run): raise Rejected("current protected run is invalid")
    package = Path(policy["package_root"]); descriptor = open_package(str(package))
    try: package_measurement = subject(descriptor)
    finally: os.close(descriptor)
    attestation = EVIDENCE_ROOT / "sourcecraft-attestation.bundle"
    return {"schema_version":"runne/native-dpk-controller-request/v1",
            **{field:policy[field] for field in expected_environment.values()},
            "candidate_sha256":policy["candidate_sha256"],"release_tuple_v3_sha256":policy["release_tuple_v3_sha256"],
            "package_snapshot_sha256":digest(snapshot(package_measurement)),"package_subject_sha256":digest(signed_subject(package_measurement)),"attestation_sha256":file_digest(attestation),"attestation_receipt_sha256":digest(_attestation_receipt(policy, run, digest(snapshot(package_measurement)), digest(signed_subject(package_measurement)), file_digest(attestation))),
            "deployment_sha256":digest(DEPLOYMENT),"role_paths":ROLE_PATHS,"role_measurements":canonical_roles(package_measurement),"workflow_run_id":run,
            "selectors":sorted(SELECTORS),"stages":list(STAGES),"executor_sha256":policy["native_executor"]["sha256"]}


def valid_run(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and value.replace("-", "a").replace("_", "a").isalnum()


def _attestation_receipt(policy: dict[str, object], run: str, snapshot: str,
                         package_subject: str, bundle: str) -> dict[str, object]:
    return {"verified":True,"repository":policy["repository"],"workflow":policy["workflow"],
            "job":policy["job"],"protected_ref":policy["protected_ref"],
            "source_revision":policy["source_revision"],"workflow_run_id":run,
            "package_snapshot_sha256":snapshot,"package_subject_sha256":package_subject,
            "bundle_sha256":bundle}


def _pre_attestation(policy: dict[str, object], request: dict[str, object],
                     production: bool) -> dict[str, object]:
    receipt = _attestation_receipt(policy, request["workflow_run_id"], request["package_snapshot_sha256"],
                                   request["package_subject_sha256"], request["attestation_sha256"])
    if not production: return receipt
    identity = policy["attestation_verifier"]; bundle = EVIDENCE_ROOT / "sourcecraft-attestation.bundle"
    output, status = run_protected([identity["path"],"--bundle",str(bundle),"--repository",policy["repository"],
                                    "--workflow",policy["workflow"],"--job",policy["job"],"--ref",policy["protected_ref"],
                                    "--source-revision",policy["source_revision"],"--run",request["workflow_run_id"],
                                    "--package-snapshot",request["package_snapshot_sha256"],"--package-subject",request["package_subject_sha256"]], None, contain=production)
    if status != 0 or parse_json(output) != receipt: raise Rejected("pre-native attestation rejected")
    return receipt


def _write_lifecycle(root: Path, value: dict[str, object]) -> None:
    if root.is_symlink() or not root.is_dir() or (root / "controller-lifecycle.json").exists():
        raise Rejected("controller lifecycle handoff is unavailable")
    try:
        descriptor = os.open(root / "controller-lifecycle.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            payload = canonical(value)
            if os.write(descriptor, payload) != len(payload): raise Rejected("controller lifecycle handoff is unavailable")
            os.fsync(descriptor)
        finally: os.close(descriptor)
    except OSError: raise Rejected("controller lifecycle handoff is unavailable") from None


def main(argv: list[str] | None = None) -> int:
    if argv not in (None, []):
        print('{"qualified":false,"reason":"controller_arguments_rejected"}'); return 1
    try:
        policy = load_installed_json(POLICY_PATH)
        verdict = handoff(build_request(policy, dict(os.environ)), policy)
    except Rejected: verdict = {"native_execution":False,"qualified":False,"reason":"controller_request_rejected"}
    print(json.dumps(verdict, sort_keys=True, separators=(",", ":")))
    return 0 if verdict.get("native_execution") and verdict.get("evidence_ready") else 1


if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
