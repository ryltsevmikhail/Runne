use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use runne_native_qualification::{
    PendingQualificationAdmission, QualificationAdmissionVerifier, VerifiedQualificationFenceFacts,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub(super) const CANDIDATE: [u8; 32] = [0xaa; 32];
pub(super) const RAW_TUPLE: [u8; 32] = [0xbb; 32];

#[derive(Serialize)]
struct Signature {
    algorithm: &'static str,
    key_id: String,
    value: String,
}

#[derive(Serialize)]
struct Ticket {
    schema_version: &'static str,
    ticket_id: String,
    selector: &'static str,
    process_role: &'static str,
    candidate_sha256: String,
    release_tuple_v3_sha256: String,
    source_revision: String,
    workflow_run_id: &'static str,
    namespace_sha256: String,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

#[derive(Serialize)]
struct Context {
    schema_version: &'static str,
    context_id: String,
    scenario_id: &'static str,
    selector: &'static str,
    process_role: &'static str,
    candidate_sha256: String,
    release_tuple_v3_sha256: String,
    source_revision: String,
    workflow_run_id: &'static str,
    namespace_sha256: String,
    ticket_sha256: String,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
}

fn sign<T: Serialize>(domain: &[u8], value: &T, key: &SigningKey) -> Signature {
    let mut payload = domain.to_vec();
    payload.extend_from_slice(&serde_json::to_vec(value).unwrap());
    Signature {
        algorithm: "ed25519",
        key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
        value: URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes()),
    }
}

pub(super) fn facts(
    ids: [u8; 4],
    issued: u64,
    expiry: u64,
    now: u64,
) -> VerifiedQualificationFenceFacts {
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let admission = admission(&context_key, &fault_key, ids, issued, expiry);
    QualificationAdmissionVerifier::test_only_from_verifying_keys(
        context_key.verifying_key(),
        fault_key.verifying_key(),
    )
    .verify_exact_for_fence_borrowed(&admission, CANDIDATE, RAW_TUPLE, now)
    .unwrap()
}

fn admission(
    context_key: &SigningKey,
    fault_key: &SigningKey,
    ids: [u8; 4],
    issued: u64,
    expiry: u64,
) -> PendingQualificationAdmission {
    let mut ticket = Ticket {
        schema_version: "runne/macos-xpc-dpk-fault-ticket/v1",
        ticket_id: hex::encode([ids[2]; 32]),
        selector: "kill_desktop_process",
        process_role: "desktop",
        candidate_sha256: hex::encode(CANDIDATE),
        release_tuple_v3_sha256: hex::encode(RAW_TUPLE),
        source_revision: "cc".repeat(20),
        workflow_run_id: "run-42",
        namespace_sha256: "dd".repeat(32),
        issued_at: issued,
        expires_at: expiry,
        nonce: URL_SAFE_NO_PAD.encode([ids[3]; 32]),
        signature: None,
    };
    ticket.signature = Some(sign(
        b"runne/macos-xpc-dpk-fault-ticket/v1\0",
        &ticket,
        fault_key,
    ));
    let ticket = serde_json::to_vec(&ticket).unwrap();
    let mut context = Context {
        schema_version: "runne/macos-xpc-dpk-run-context/v1",
        context_id: hex::encode([ids[0]; 32]),
        scenario_id: "macos-xpc-dpk-v1",
        selector: "kill_desktop_process",
        process_role: "desktop",
        candidate_sha256: hex::encode(CANDIDATE),
        release_tuple_v3_sha256: hex::encode(RAW_TUPLE),
        source_revision: "cc".repeat(20),
        workflow_run_id: "run-42",
        namespace_sha256: "dd".repeat(32),
        ticket_sha256: hex::encode(Sha256::digest(&ticket)),
        issued_at: issued,
        expires_at: expiry,
        nonce: URL_SAFE_NO_PAD.encode([ids[1]; 32]),
        signature: None,
    };
    context.signature = Some(sign(
        b"runne/macos-xpc-dpk-run-context/v1\0",
        &context,
        context_key,
    ));
    let context = serde_json::to_vec(&context).unwrap();
    let mut bundle = Vec::with_capacity(17 + context.len() + ticket.len());
    bundle.extend_from_slice(b"RNQADM1\0");
    bundle.push(1);
    bundle.extend_from_slice(&u32::try_from(context.len()).unwrap().to_be_bytes());
    bundle.extend_from_slice(&u32::try_from(ticket.len()).unwrap().to_be_bytes());
    bundle.extend_from_slice(&context);
    bundle.extend_from_slice(&ticket);
    PendingQualificationAdmission::from_admitted_bundle(bundle).unwrap()
}
