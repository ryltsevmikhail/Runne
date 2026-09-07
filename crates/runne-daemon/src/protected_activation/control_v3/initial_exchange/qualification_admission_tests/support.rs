use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use runne_api::{
    QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationRunContextRelayBindingV1, QualificationRunContextRelayDirectionV1,
};
use runne_native_qualification::{
    PendingQualificationAdmission, QualificationAdmissionRelayCodecV1,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub(super) const NOW: u64 = 1_800_000_000;
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

pub(in crate::protected_activation::control_v3::initial_exchange) fn admission(
    context_key: &SigningKey,
    fault_key: &SigningKey,
) -> PendingQualificationAdmission {
    admission_at(context_key, fault_key, NOW)
}

pub(in crate::protected_activation::control_v3::initial_exchange) fn admission_at(
    context_key: &SigningKey,
    fault_key: &SigningKey,
    now: u64,
) -> PendingQualificationAdmission {
    PendingQualificationAdmission::from_admitted_bundle(admission_bundle_at(
        context_key,
        fault_key,
        now,
        "kill_desktop_process",
        "desktop",
    ))
    .unwrap()
}

pub(in crate::protected_activation::control_v3::initial_exchange) fn writer_admission_at(
    context_key: &SigningKey,
    fault_key: &SigningKey,
    now: u64,
) -> PendingQualificationAdmission {
    PendingQualificationAdmission::from_admitted_bundle(writer_admission_bundle_at(
        context_key,
        fault_key,
        now,
    ))
    .unwrap()
}

pub(in crate::protected_activation::control_v3::initial_exchange) fn writer_admission_bundle_at(
    context_key: &SigningKey,
    fault_key: &SigningKey,
    now: u64,
) -> Vec<u8> {
    writer_admission_bundle_for_at(context_key, fault_key, now, CANDIDATE, RAW_TUPLE)
}

pub(crate) fn writer_admission_bundle_for_at(
    context_key: &SigningKey,
    fault_key: &SigningKey,
    now: u64,
    candidate: [u8; 32],
    raw_tuple: [u8; 32],
) -> Vec<u8> {
    admission_bundle_with_digests_at(
        context_key,
        fault_key,
        now,
        "kill_writer_process",
        "writer",
        candidate,
        raw_tuple,
    )
}

pub(super) fn admission_bundle_at(
    context_key: &SigningKey,
    fault_key: &SigningKey,
    now: u64,
    selector: &'static str,
    process_role: &'static str,
) -> Vec<u8> {
    admission_bundle_with_digests_at(
        context_key,
        fault_key,
        now,
        selector,
        process_role,
        CANDIDATE,
        RAW_TUPLE,
    )
}

#[allow(clippy::too_many_arguments)]
fn admission_bundle_with_digests_at(
    context_key: &SigningKey,
    fault_key: &SigningKey,
    now: u64,
    selector: &'static str,
    process_role: &'static str,
    candidate: [u8; 32],
    raw_tuple: [u8; 32],
) -> Vec<u8> {
    let mut ticket = Ticket {
        schema_version: "runne/macos-xpc-dpk-fault-ticket/v1",
        ticket_id: "11".repeat(32),
        selector,
        process_role,
        candidate_sha256: hex::encode(candidate),
        release_tuple_v3_sha256: hex::encode(raw_tuple),
        source_revision: "cc".repeat(20),
        workflow_run_id: "run-42",
        namespace_sha256: "dd".repeat(32),
        issued_at: now,
        expires_at: now + 600,
        nonce: URL_SAFE_NO_PAD.encode([0x22; 32]),
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
        context_id: "33".repeat(32),
        scenario_id: "macos-xpc-dpk-v1",
        selector,
        process_role,
        candidate_sha256: hex::encode(candidate),
        release_tuple_v3_sha256: hex::encode(raw_tuple),
        source_revision: "cc".repeat(20),
        workflow_run_id: "run-42",
        namespace_sha256: "dd".repeat(32),
        ticket_sha256: hex::encode(Sha256::digest(&ticket)),
        issued_at: now,
        expires_at: now + 300,
        nonce: URL_SAFE_NO_PAD.encode([0x44; 32]),
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
    bundle
}

pub(super) fn bindings(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> (
    QualificationRunContextRelayBindingV1,
    QualificationFaultRelayBindingV1,
) {
    let session = *owned.session_id();
    let release = *owned.enrollment_binding().release_tuple_digest();
    (
        QualificationRunContextRelayBindingV1::new(
            session,
            release,
            owned.launch_generation(),
            QualificationRunContextRelayDirectionV1::DesktopToRuntime,
            1,
        )
        .unwrap(),
        QualificationFaultRelayBindingV1::new(
            session,
            release,
            owned.launch_generation(),
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            1,
        )
        .unwrap(),
    )
}

pub(in crate::protected_activation::control_v3::initial_exchange) fn relay(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    keys: &runne_api::ProtectedActivationKeys,
    context_key: &SigningKey,
    fault_key: &SigningKey,
) -> Vec<u8> {
    let (context_binding, fault_binding) = bindings(owned);
    relay_with_bindings(
        keys,
        context_key,
        fault_key,
        &context_binding,
        &fault_binding,
    )
}

pub(super) fn relay_with_bindings(
    keys: &runne_api::ProtectedActivationKeys,
    context_key: &SigningKey,
    fault_key: &SigningKey,
    context_binding: &QualificationRunContextRelayBindingV1,
    fault_binding: &QualificationFaultRelayBindingV1,
) -> Vec<u8> {
    admission(context_key, fault_key)
        .encode_relay_transcript(
            &QualificationAdmissionRelayCodecV1::from_protected_activation(keys),
            context_binding,
            fault_binding,
        )
        .unwrap()
        .into_bytes()
}

pub(in crate::protected_activation::control_v3::initial_exchange) fn outer(
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
