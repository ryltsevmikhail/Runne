use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use runne_native_qualification::{
    PendingQualificationAdmission, QualificationAdmissionVerifier, QualificationFaultSelector,
    QualificationProcessRole, QualificationRunContextExpectation, QualificationScenario,
    VerifiedQualificationFenceFacts,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const NOW: u64 = 1_800_000_000;

#[derive(Clone, Serialize)]
struct Signature {
    algorithm: &'static str,
    key_id: String,
    value: String,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Serialize)]
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
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Serialize)]
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
}

#[derive(Serialize)]
struct Signed<T> {
    #[serde(flatten)]
    value: T,
    signature: Signature,
}

pub(super) fn facts(ids: [u8; 4]) -> VerifiedQualificationFenceFacts {
    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    let ticket = Ticket {
        schema_version: "runne/macos-xpc-dpk-fault-ticket/v1",
        ticket_id: hex::encode([ids[2]; 32]),
        selector: "kill_before_native_effect",
        process_role: "service",
        candidate_sha256: hex::encode([0xaa; 32]),
        release_tuple_v3_sha256: hex::encode([0xbb; 32]),
        source_revision: hex::encode([0xcc; 20]),
        workflow_run_id: "run-42",
        namespace_sha256: hex::encode([0xdd; 32]),
        issued_at: NOW,
        expires_at: NOW + 600,
        nonce: URL_SAFE_NO_PAD.encode([ids[3]; 32]),
    };
    let ticket = sign(ticket, &fault_key, b"runne/macos-xpc-dpk-fault-ticket/v1\0");
    let context = Context {
        schema_version: "runne/macos-xpc-dpk-run-context/v1",
        context_id: hex::encode([ids[0]; 32]),
        scenario_id: "macos-xpc-dpk-v1",
        selector: "kill_before_native_effect",
        process_role: "service",
        candidate_sha256: hex::encode([0xaa; 32]),
        release_tuple_v3_sha256: hex::encode([0xbb; 32]),
        source_revision: hex::encode([0xcc; 20]),
        workflow_run_id: "run-42",
        namespace_sha256: hex::encode([0xdd; 32]),
        ticket_sha256: hex::encode(Sha256::digest(&ticket)),
        issued_at: NOW,
        expires_at: NOW + 300,
        nonce: URL_SAFE_NO_PAD.encode([ids[1]; 32]),
    };
    let context = sign(
        context,
        &context_key,
        b"runne/macos-xpc-dpk-run-context/v1\0",
    );
    let admission = PendingQualificationAdmission::from_admitted_bundle(bundle(&context, &ticket))
        .expect("canonical signed fixture");
    let expected = QualificationRunContextExpectation::new(
        QualificationScenario::MacosXpcDpkV1,
        QualificationFaultSelector::BeforeNativeEffect,
        QualificationProcessRole::Service,
        [0xaa; 32],
        [0xbb; 32],
        [0xcc; 20],
        "run-42",
        [0xdd; 32],
        Sha256::digest(&ticket).into(),
    )
    .expect("canonical expectation");
    QualificationAdmissionVerifier::test_only_from_verifying_keys(
        context_key.verifying_key(),
        fault_key.verifying_key(),
    )
    .verify_and_consume(&admission, &expected, NOW)
    .expect("verified fixture facts")
}

fn sign<T: Clone + Serialize>(value: T, key: &SigningKey, domain: &[u8]) -> Vec<u8> {
    let unsigned = serde_json::to_vec(&value).expect("canonical unsigned fixture");
    let mut payload = domain.to_vec();
    payload.extend_from_slice(&unsigned);
    let signature = key.sign(&payload);
    serde_json::to_vec(&Signed {
        value,
        signature: Signature {
            algorithm: "ed25519",
            key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })
    .expect("canonical signed fixture")
}

fn bundle(context: &[u8], ticket: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(17 + context.len() + ticket.len());
    bytes.extend_from_slice(b"RNQADM1\0");
    bytes.push(1);
    bytes.extend_from_slice(&u32::try_from(context.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(ticket.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(context);
    bytes.extend_from_slice(ticket);
    bytes
}
