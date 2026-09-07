use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

const TICKET_DOMAIN: &[u8] = b"runne/macos-xpc-dpk-fault-ticket/v1\0";
const CONTEXT_DOMAIN: &[u8] = b"runne/macos-xpc-dpk-run-context/v1\0";

#[derive(Clone, Copy, Debug)]
pub(super) enum AdmissionMutation {
    Valid,
    BadContextKey,
    BadFaultKey,
    Expired,
    WrongRole,
    CandidateMismatch,
    TupleMismatch,
}

pub(super) fn signed_writer_admission(
    now: u64,
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
) -> (
    Vec<u8>,
    runne_native_qualification::QualificationAdmissionVerifier,
) {
    signed_writer_admission_case(
        now,
        candidate_sha256,
        raw_v3_tuple_sha256,
        AdmissionMutation::Valid,
    )
}

pub(super) fn signed_writer_admission_case(
    now: u64,
    mut candidate_sha256: [u8; 32],
    mut raw_v3_tuple_sha256: [u8; 32],
    mutation: AdmissionMutation,
) -> (
    Vec<u8>,
    runne_native_qualification::QualificationAdmissionVerifier,
) {
    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    if matches!(mutation, AdmissionMutation::CandidateMismatch) {
        candidate_sha256[0] ^= 0xff;
    }
    if matches!(mutation, AdmissionMutation::TupleMismatch) {
        raw_v3_tuple_sha256[0] ^= 0xff;
    }
    let issued_at = if matches!(mutation, AdmissionMutation::Expired) {
        now.saturating_sub(20)
    } else {
        now
    };
    let (context_expires_at, ticket_expires_at) = if matches!(mutation, AdmissionMutation::Expired)
    {
        (now.saturating_sub(2), now.saturating_sub(1))
    } else {
        (now + 300, now + 600)
    };
    let (selector, role) = if matches!(mutation, AdmissionMutation::WrongRole) {
        ("kill_before_service_consume", "service")
    } else {
        ("kill_writer_process", "writer")
    };
    let fault_signer = if matches!(mutation, AdmissionMutation::BadFaultKey) {
        SigningKey::from_bytes(&[8; 32])
    } else {
        fault_key.clone()
    };
    let context_signer = if matches!(mutation, AdmissionMutation::BadContextKey) {
        SigningKey::from_bytes(&[10; 32])
    } else {
        context_key.clone()
    };
    let ticket = signed_ticket(
        issued_at,
        ticket_expires_at,
        selector,
        role,
        (candidate_sha256, raw_v3_tuple_sha256),
        &fault_signer,
    );
    let context = signed_context(
        issued_at,
        context_expires_at,
        selector,
        role,
        (candidate_sha256, raw_v3_tuple_sha256),
        Sha256::digest(&ticket).into(),
        &context_signer,
    );
    let mut bundle = Vec::with_capacity(17 + context.len() + ticket.len());
    bundle.extend_from_slice(b"RNQADM1\0");
    bundle.push(1);
    bundle.extend_from_slice(&(context.len() as u32).to_be_bytes());
    bundle.extend_from_slice(&(ticket.len() as u32).to_be_bytes());
    bundle.extend_from_slice(&context);
    bundle.extend_from_slice(&ticket);
    let verifier =
        runne_native_qualification::QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        );
    (bundle, verifier)
}

fn signed_ticket(
    issued_at: u64,
    expires_at: u64,
    selector: &str,
    role: &str,
    installed: ([u8; 32], [u8; 32]),
    key: &SigningKey,
) -> Vec<u8> {
    let unsigned = format!(
        concat!(
            "{{\"schema_version\":\"runne/macos-xpc-dpk-fault-ticket/v1\",",
            "\"ticket_id\":\"{}\",\"selector\":\"{}\",",
            "\"process_role\":\"{}\",\"candidate_sha256\":\"{}\",",
            "\"release_tuple_v3_sha256\":\"{}\",\"source_revision\":\"{}\",",
            "\"workflow_run_id\":\"run-42\",\"namespace_sha256\":\"{}\",",
            "\"issued_at\":{},\"expires_at\":{},\"nonce\":\"{}\"}}"
        ),
        "11".repeat(32),
        selector,
        role,
        hex::encode(installed.0),
        hex::encode(installed.1),
        "cc".repeat(20),
        "dd".repeat(32),
        issued_at,
        expires_at,
        URL_SAFE_NO_PAD.encode([0x22; 32]),
    );
    append_signature(unsigned, TICKET_DOMAIN, key)
}

fn signed_context(
    issued_at: u64,
    expires_at: u64,
    selector: &str,
    role: &str,
    installed: ([u8; 32], [u8; 32]),
    ticket_sha256: [u8; 32],
    key: &SigningKey,
) -> Vec<u8> {
    let unsigned = format!(
        concat!(
            "{{\"schema_version\":\"runne/macos-xpc-dpk-run-context/v1\",",
            "\"context_id\":\"{}\",\"scenario_id\":\"macos-xpc-dpk-v1\",",
            "\"selector\":\"{}\",\"process_role\":\"{}\",",
            "\"candidate_sha256\":\"{}\",\"release_tuple_v3_sha256\":\"{}\",",
            "\"source_revision\":\"{}\",\"workflow_run_id\":\"run-42\",",
            "\"namespace_sha256\":\"{}\",\"ticket_sha256\":\"{}\",",
            "\"issued_at\":{},\"expires_at\":{},\"nonce\":\"{}\"}}"
        ),
        "33".repeat(32),
        selector,
        role,
        hex::encode(installed.0),
        hex::encode(installed.1),
        "cc".repeat(20),
        "dd".repeat(32),
        hex::encode(ticket_sha256),
        issued_at,
        expires_at,
        URL_SAFE_NO_PAD.encode([0x44; 32]),
    );
    append_signature(unsigned, CONTEXT_DOMAIN, key)
}

fn append_signature(unsigned: String, domain: &[u8], key: &SigningKey) -> Vec<u8> {
    let mut payload = Vec::with_capacity(domain.len() + unsigned.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(unsigned.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&payload).to_bytes());
    let key_id = hex::encode(Sha256::digest(key.verifying_key().as_bytes()));
    format!(
        "{},\"signature\":{{\"algorithm\":\"ed25519\",\"key_id\":\"{}\",\"value\":\"{}\"}}}}",
        unsigned.strip_suffix('}').unwrap(),
        key_id,
        signature,
    )
    .into_bytes()
}
