from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from codec import canonical, digest
from contract import DEPLOYMENT, ROLE_PATHS, SELECTORS, STORE, TUPLE, tuple_digest
from ed25519_verify import _B, _L, _mul

NOW = "2026-09-08T12:00:00Z"

def _hash(value: str) -> str: return hashlib.sha256(value.encode()).hexdigest()

def _authority_modules(root: str = "/test") -> dict[str, object]:
    from policy import MODULES
    return {name:{"path":f"{root}/{name}","sha256":_hash(name)} for name in MODULES}


def _signature(message: bytes) -> tuple[bytes, bytes]:
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    expanded = hashlib.sha512(seed).digest(); scalar = int.from_bytes(expanded[:32], "little")
    scalar &= (1 << 254) - 8; scalar |= 1 << 254
    x, y = _mul(scalar, _B); public = (y | ((x & 1) << 255)).to_bytes(32, "little")
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % _L
    x, y = _mul(nonce, _B); encoded = (y | ((x & 1) << 255)).to_bytes(32, "little")
    challenge = int.from_bytes(hashlib.sha512(encoded + public + message).digest(), "little") % _L
    return public, encoded + ((nonce + challenge * scalar) % _L).to_bytes(32, "little")


def _resign(value: dict[str, object], *, refresh_inventory: bool = True) -> None:
    """Rebuild every outer digest/signature for semantic-negative vectors."""
    files, package = value["files"], value["package"]
    assert isinstance(files, dict) and isinstance(package, dict)
    raw = {name:base64.b64decode(item["base64"]) for name,item in package.items()}
    hashes = {name:hashlib.sha256(item).hexdigest() for name,item in raw.items()}
    row, tuples = files["macos-13-arm64.json"], files["expected-tuples.json"]
    assert isinstance(row, dict) and isinstance(tuples, dict); tuple_value = tuples["arm64"]
    assert isinstance(tuple_value, dict); identities = row["code_identities"]
    assert isinstance(identities, dict)
    for role, path in ROLE_PATHS.items():
        identity = identities[role]; assert isinstance(identity, dict)
        tuple_value[f"{role}_sha256"] = hashes[path]
        tuple_value[f"{role}_code_identity_sha256"] = digest(identity)
    tuple_value["tuple_sha256"] = tuple_digest(tuple_value)
    roles = files["artifact-manifest.json"]["role_measurements"]
    assert isinstance(roles, dict)
    row["artifact_scan"]["scan_subject_sha256"] = digest({"package_files":hashes,"role_measurements":roles,"canary":"runne/native-qualification-export-canary/v1"})
    manifest = files["artifact-manifest.json"]; assert isinstance(manifest, dict)
    manifest["row_sha256"] = digest(row); manifest["expected_tuples_sha256"] = digest(tuples)
    if refresh_inventory:
        manifest["package_files"] = [{"name":name,"sha256":hashes[name]} for name in package]
    manifest["files"] = [{"name":name,"sha256":hashlib.sha256(canonical(item) if not isinstance(item, str) else item.encode()).hexdigest()} for name,item in sorted(files.items()) if name not in {"artifact-manifest.json","signed-envelope.json","controller-conformance.json"}]
    conformance = files["controller-conformance.json"]; assert isinstance(conformance, dict)
    conformance["artifact_manifest_sha256"] = digest(manifest)
    lifecycle = files["controller-lifecycle.json"]; assert isinstance(lifecycle, dict)
    conformance["controller_lifecycle_sha256"] = digest(lifecycle)
    envelope = files["signed-envelope.json"]; assert isinstance(envelope, dict)
    envelope.update(row_sha256=digest(row),expected_tuples_sha256=digest(tuples),artifact_manifest_sha256=digest(manifest),conformance_sha256=digest(conformance),controller_lifecycle_sha256=digest(lifecycle))
    unsigned = {name:item for name,item in envelope.items() if name != "signature"}
    _, signed = _signature(b"runne/macos-xpc-service-qualification/v1\0" + canonical(unsigned))
    envelope["signature"] = {"algorithm":"ed25519","value":base64.urlsafe_b64encode(signed).decode()}


def _bind_lifecycle_package(value: dict[str, object]) -> None:
    files, package = value["files"], value["package"]
    assert isinstance(files, dict) and isinstance(package, dict)
    hashes = {name:hashlib.sha256(base64.b64decode(item["base64"])).hexdigest() for name,item in package.items()}
    roles = files["artifact-manifest.json"]["role_measurements"]
    lifecycle = files["controller-lifecycle.json"]
    assert isinstance(roles, dict) and isinstance(lifecycle, dict)
    lifecycle["package_snapshot_sha256"] = digest(hashes)
    lifecycle["package_subject_sha256"] = digest({"files":{path:roles[role] for role,path in ROLE_PATHS.items()},"roles":roles})
    bundle = files["sourcecraft-attestation.bundle"]; assert isinstance(bundle, str)
    lifecycle["attestation_sha256"] = hashlib.sha256(bundle.encode()).hexdigest()
    policy = value["policy"]; assert isinstance(policy, dict)
    receipt = {"verified":True,"repository":policy["repository"],"workflow":policy["workflow"],"job":policy["job"],"protected_ref":policy["protected_ref"],"source_revision":policy["source_revision"],"workflow_run_id":lifecycle["workflow_run_id"],"package_snapshot_sha256":lifecycle["package_snapshot_sha256"],"package_subject_sha256":lifecycle["package_subject_sha256"],"bundle_sha256":lifecycle["attestation_sha256"]}
    request = {"schema_version":"runne/native-dpk-controller-request/v1",**{name:policy[name] for name in ("repository","workflow","job","protected_ref","source_revision","candidate_sha256","release_tuple_v3_sha256")},"package_snapshot_sha256":lifecycle["package_snapshot_sha256"],"package_subject_sha256":lifecycle["package_subject_sha256"],"attestation_sha256":lifecycle["attestation_sha256"],"attestation_receipt_sha256":digest(receipt),"deployment_sha256":digest(DEPLOYMENT),"role_paths":ROLE_PATHS,"role_measurements":roles,"workflow_run_id":lifecycle["workflow_run_id"],"selectors":sorted(SELECTORS),"stages":["install_exact_package","open_isolated_user","issue_case_ticket","observe_signal","terminal_readback","exact_locator_cleanup","scan_exports","emit_signed_evidence"],"executor_sha256":policy["native_executor"]["sha256"]}
    preflight = {"schema_version":"runne/native-dpk-preflight-result/v1","request_sha256":digest(request),"package_snapshot_sha256":lifecycle["package_snapshot_sha256"],"package_subject_sha256":lifecycle["package_subject_sha256"],"developer_id_verified":True,"notarized":True,"provisioning_verified":True,"role_paths":ROLE_PATHS,"role_measurements":roles,"deployment_sha256":digest(DEPLOYMENT),"attestation_sha256":lifecycle["attestation_sha256"],"attestation_receipt_sha256":digest(receipt)}
    result = {"schema_version":"runne/native-dpk-controller-result/v1","workflow_run_id":lifecycle["workflow_run_id"],"request_sha256":digest(request),"package_snapshot_sha256":lifecycle["package_snapshot_sha256"],"package_subject_sha256":lifecycle["package_subject_sha256"],"evidence_ready":True,"cleanup_verified":True}
    lifecycle.update(request_sha256=digest(request),attestation_receipt_sha256=digest(receipt),preflight_sha256=digest(preflight),result_sha256=digest(result))


def _vector() -> dict[str, object]:
    public, _ = _signature(b"")
    policy = {"schema_version":"runne/sourcecraft-native-qualification-policy/v1","policy_id":"runne/writer-qualification/v1","repository":"https://git@git.sourcecraft.dev/ryltsevmg/runne.git","workflow":"desktop-qualification","job":"qualification-native-macos","protected_ref":"refs/tags/v1.0.0","source_revision":"a" * 40,"candidate_sha256":_hash("candidate"),"release_tuple_v3_sha256":_hash("release"),"candidate_root":"/candidate","package_root":"/test/package","controller":{"path":"/test/controller","sha256":_hash("controller")},"verifier":{"path":"/test/verifier","sha256":_hash("verifier")},"native_executor":{"path":"/opt/gocode/sourcecraft/bin/runne-native-dpk-executor","sha256":_hash("executor")},"attestation_verifier":{"path":"/test/attestation","sha256":_hash("attestation")},"evidence_signer":{"path":"/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-sign-evidence","sha256":_hash("signer")},"signer_broker":{"path":"/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-signer-broker","sha256":_hash("broker")},"authority_modules":_authority_modules(),"evidence_authority":{"key_id":hashlib.sha256(public).hexdigest(),"public_key":public.hex()},"writer_profile":{"attestation":2,"prelude":1,"ack":1},"test_only":True}
    package_bytes = {path:b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01" + role.encode() for role,path in ROLE_PATHS.items()}
    package = {path:{"base64":base64.b64encode(value).decode()} for path,value in package_bytes.items()}
    package_hashes = {path:hashlib.sha256(value).hexdigest() for path,value in package_bytes.items()}
    role_measurements = {role:{"sha256":package_hashes[path],"size":len(package_bytes[path]),"macho_magic":"cffaedfe","architecture":"arm64","canary_matches":0}
                         for role,path in ROLE_PATHS.items()}
    tuple_value = {name:_hash(name) for name in TUPLE}; tuple_value.update(candidate_sha256=policy["candidate_sha256"], release_tuple_v3_sha256=policy["release_tuple_v3_sha256"], deployment_sha256=digest(DEPLOYMENT))
    identities = {role:{"identifier":{"desktop":"com.runne.desktop","writer":"runne","daemon":"runned","service":"com.runne.credential-service"}[role],"teamIdentifier":"758F9Z45SR","cdhash":str(index + 1) * 40} for index,role in enumerate(("desktop","writer","daemon","service"))}
    for role in identities: tuple_value[f"{role}_sha256"] = package_hashes[ROLE_PATHS[role]]; tuple_value[f"{role}_code_identity_sha256"] = digest(identities[role])
    tuple_value["tuple_sha256"] = tuple_digest(tuple_value)
    selectors = {}
    for ordinal,name in enumerate(sorted(SELECTORS)):
        status = "unsupported" if name == "remote_verify_after_local" else "verified"
        semantic = {"case_receipt":{"ordinal":ordinal,"selector":name,"workflow_run_id":"vector-run-1"},"process_signal":{"outcome":status,"selector":name},"terminal_state":{"cleanup_verified":True,"selector":name,"state":status},"namespace":{"exact_cleanup":True,"selector":name}}
        receipt_hashes = {"ticket_sha256":digest(semantic["case_receipt"]),"process_signal_sha256":digest(semantic["process_signal"]),"terminal_state_sha256":digest(semantic["terminal_state"]),"namespace_sha256":digest(semantic["namespace"])}
        selectors[name] = {"status":status,"workflow_run_id":"vector-run-1",**semantic,**receipt_hashes}
    selectors["local_verify_no_network"]["network_attempts"] = 0; selectors["remote_verify_after_local"].update(local_verification="verified", retry_count=0)
    scan_subject = digest({"package_files":package_hashes,"role_measurements":role_measurements,"canary":"runne/native-qualification-export-canary/v1"})
    row = {"platform":"macos","architecture":"arm64","os_version":"14.6","disposition":"verified","tuple":tuple_value,"signing":{"profile":"developer_id","notarized":True,"ad_hoc":False,"team_id":"758F9Z45SR","code_identifiers":{"desktop":"com.runne.desktop","writer":"runne","daemon":"runned","service":"com.runne.credential-service"},"application_identifiers":{"desktop":"758F9Z45SR.com.runne.desktop","service":"758F9Z45SR.com.runne.credential-service"}},"code_identities":identities,"runner":{"workflow_run_id":"vector-run-1","attestation_verified":True,"freshness_verified":True,"isolated_disposable_user":True,"icloud_data_present":False,"user_keychain_data_present":False},"native_store":STORE,"artifact_scan":{"files_scanned":10,"sensitive_value_matches":0,"scan_subject_sha256":scan_subject,"canary_sha256":digest({"needle":"runne/native-qualification-export-canary/v1","matches":0})},"selectors":selectors,"deployment":DEPLOYMENT}
    receipts = {"attestation":{"profile":2,"status":"verified"},"prelude":{"version":1,"status":"verified"},"ack":{"version":1,"status":"verified"}}
    tuples = {"arm64":tuple_value}; transcript = {"schema_version":"runne/writer-qualified-transcript/v2","role":"writer","profile":"runne/writer-qualification/v1","attestation":2,"prelude":1,"ack":1,"status":"verified","workflow_run_id":"vector-run-1","tuple_sha256":tuple_value["tuple_sha256"],**{f"{name}_receipt":value for name,value in receipts.items()},**{f"{name}_sha256":digest(value) for name,value in receipts.items()}}
    service_receipts = {"admission":{"source_role":"daemon","status":"verified","target_role":"credential-service"},"endpoint":{"endpoint":"com.runne.credential-service.writer.v1","status":"verified"}}
    service = {"schema_version":"runne/service-direct-admission/v1","source_role":"daemon","target_role":"credential-service","direct_admission":"verified","ordinary_writer_v1":"role_routing_only","workflow_run_id":"vector-run-1","tuple_sha256":tuple_value["tuple_sha256"],**{f"{name}_receipt":value for name,value in service_receipts.items()},**{f"{name}_sha256":digest(value) for name,value in service_receipts.items()}}; bundle = "test-only-attestation-bundle"
    signed_package = {"files":{path:role_measurements[role] for role,path in ROLE_PATHS.items()},"roles":role_measurements}
    lifecycle = {"schema_version":"runne/native-dpk-controller-lifecycle/v1","order":["request","preflight","execute","complete"],"workflow_run_id":"vector-run-1","request_sha256":_hash("request"),"package_snapshot_sha256":digest(package_hashes),"package_subject_sha256":digest(signed_package),"attestation_sha256":hashlib.sha256(bundle.encode()).hexdigest(),"attestation_receipt_sha256":_hash("attestation-receipt"),"preflight_sha256":_hash("preflight"),"result_sha256":_hash("result"),"outcome":"cleanup_verified"}
    files = {"macos-13-arm64.json":row,"expected-tuples.json":tuples,"writer-transcript-v2.json":transcript,"service-admission.json":service,"sourcecraft-attestation.bundle":bundle,"controller-lifecycle.json":lifecycle}
    manifest = {"schema_version":"runne/native-qualification-artifact-manifest/v1","row_sha256":digest(row),"expected_tuples_sha256":digest(tuples),"native_measurements_sha256":digest({name:tuple_value[name] for name in ("launch_agent_plist_sha256","entitlements_sha256","provisioning_sha256","protocol_sha256","contract_sha256")}),"files":[{"name":name,"sha256":hashlib.sha256(canonical(value) if not isinstance(value, str) else value.encode()).hexdigest()} for name,value in sorted(files.items())],"package_files":[{"name":name,"sha256":package_hashes[name]} for name in package],"role_paths":ROLE_PATHS,"role_measurements":role_measurements}
    conformance = {"schema_version":"runne/native-qualification-conformance/v1","policy_id":policy["policy_id"],"candidate_sha256":policy["candidate_sha256"],"release_tuple_v3_sha256":policy["release_tuple_v3_sha256"],"controller":policy["controller"],"writer_transcript_sha256":digest(transcript),"service_admission_sha256":digest(service),"controller_lifecycle_sha256":digest(lifecycle),"cleanup_verified":True,"artifact_manifest_sha256":digest(manifest)}
    envelope = {"schema_version":"macos-xpc-service-signed-envelope.v1","source_revision":policy["source_revision"],"workflow_run_id":"vector-run-1","namespace_sha256":_hash("namespace"),"signer_key_id":policy["evidence_authority"]["key_id"],"row_sha256":digest(row),"expected_tuples_sha256":digest(tuples),"artifact_manifest_sha256":digest(manifest),"conformance_sha256":digest(conformance),"writer_transcript_sha256":digest(transcript),"service_admission_sha256":digest(service),"controller_lifecycle_sha256":digest(lifecycle),"started_at":"2026-09-08T10:00:00Z","finished_at":"2026-09-08T10:30:00Z","cleanup_verified":True}
    _, signed = _signature(b"runne/macos-xpc-service-qualification/v1\0" + canonical(envelope)); envelope["signature"] = {"algorithm":"ed25519","value":base64.urlsafe_b64encode(signed).decode()}
    files.update({"artifact-manifest.json":manifest,"signed-envelope.json":envelope,"controller-conformance.json":conformance})
    value = {"policy":policy,"files":files,"package":package,"attestation":{"test_only":True,"workflow_run_id":"vector-run-1"},"now":NOW}
    _bind_lifecycle_package(value); _resign(value)
    return value


def _negative_row_workflow() -> dict[str, object]:
    value = _vector(); row = value["files"]["macos-13-arm64.json"]
    assert isinstance(row, dict); row["runner"]["workflow_run_id"] = "other-run"
    for receipt in row["selectors"].values():
        receipt["workflow_run_id"] = "other-run"; receipt["case_receipt"]["workflow_run_id"] = "other-run"
        receipt["ticket_sha256"] = digest(receipt["case_receipt"])
    _resign(value); return value


def _negative_selector_fact() -> dict[str, object]:
    value = _vector(); receipt = value["files"]["macos-13-arm64.json"]["selectors"]["rotation"]
    assert isinstance(receipt, dict); receipt["process_signal"] = {"outcome":"fabricated","selector":"rotation"}
    receipt["process_signal_sha256"] = digest(receipt["process_signal"])
    _resign(value); return value
