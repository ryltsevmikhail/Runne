use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[derive(Serialize)]
struct RunContextFixture {
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
    signature: SignatureFixture,
}

#[derive(Serialize)]
struct TicketFixture {
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
    signature: SignatureFixture,
}

#[derive(Serialize)]
struct SignatureFixture {
    algorithm: &'static str,
    key_id: String,
    value: String,
}

pub fn ticket(id: u8) -> Vec<u8> {
    serde_json::to_vec(&TicketFixture {
        schema_version: "runne/macos-xpc-dpk-fault-ticket/v1",
        ticket_id: format!("{id:02x}").repeat(32),
        selector: "kill_before_native_effect",
        process_role: "service",
        candidate_sha256: "aa".repeat(32),
        release_tuple_v3_sha256: "bb".repeat(32),
        source_revision: "cc".repeat(20),
        workflow_run_id: "run-42",
        namespace_sha256: "dd".repeat(32),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_600,
        nonce: URL_SAFE_NO_PAD.encode([id; 32]),
        signature: signature(),
    })
    .expect("canonical ticket fixture")
}

pub fn context(ticket: &[u8], id: u8) -> Vec<u8> {
    serde_json::to_vec(&RunContextFixture {
        schema_version: "runne/macos-xpc-dpk-run-context/v1",
        context_id: format!("{id:02x}").repeat(32),
        scenario_id: "macos-xpc-dpk-v1",
        selector: "kill_before_native_effect",
        process_role: "service",
        candidate_sha256: "aa".repeat(32),
        release_tuple_v3_sha256: "bb".repeat(32),
        source_revision: "cc".repeat(20),
        workflow_run_id: "run-42",
        namespace_sha256: "dd".repeat(32),
        ticket_sha256: hex::encode(Sha256::digest(ticket)),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_300,
        nonce: URL_SAFE_NO_PAD.encode([id; 32]),
        signature: signature(),
    })
    .expect("canonical run-context fixture")
}

pub fn admission_bundle(context: &[u8], ticket: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(17 + context.len() + ticket.len());
    bytes.extend_from_slice(b"RNQADM1\0");
    bytes.push(1);
    bytes.extend_from_slice(&u32::try_from(context.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(ticket.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(context);
    bytes.extend_from_slice(ticket);
    bytes
}

fn signature() -> SignatureFixture {
    SignatureFixture {
        algorithm: "ed25519",
        key_id: "ee".repeat(32),
        value: URL_SAFE_NO_PAD.encode([0x55; 64]),
    }
}
