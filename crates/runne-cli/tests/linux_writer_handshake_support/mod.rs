//! Support for the B8/B10 real-writer handshake fixture: fixture transfer
//! authority, /proc oracles, writer spawning, and the daemon-side CONTROL
//! attestation signer helper.

// The fixture module is included verbatim by test and example crates whose
// roots are private: nursery's redundant_pub_crate asks for `pub`, while
// pedantic's missing_panics_doc/must_use_candidate then demand full public
// documentation on test-only helpers. Crate visibility plus this one reasoned
// opt-out resolves that conflict without weakening anything.
#![allow(clippy::redundant_pub_crate)]
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchSecret,
    ProtectedCredentialEnrollmentAdmissionBinding, ProtectedCredentialEnrollmentAuthenticator,
    ProtectedCredentialEnrollmentControlFrame, ProtectedCredentialEnrollmentRequestBinding,
    ProviderCredentialBrokerTransferAuthority, ProviderCredentialRequestAuthorityIssuer,
};
use runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1;
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerTarget, CredentialFence, CredentialInstallationOwnerId,
    CredentialIssueTicketBindingV1, CredentialLifecycleRevision, CredentialOperationAction,
    CredentialOperationId, CredentialTicketAttempt, CredentialVersionRef,
    CredentialWriterSessionAttestationClaimsV1, CredentialWriterSessionAttestationV2Codec,
    CredentialWriterSessionProcessClaimsV1, CredentialWriterSessionRuntimeClaimsV1,
    CredentialWriterSessionTicketClaimsV1, ProviderId,
};
use sha2::{Digest as _, Sha256};

pub(crate) const LAUNCH_SECRET: [u8; 32] = [7; 32];
pub(crate) const CHANNEL: [u8; 32] = [31; 32];
pub(crate) const PUBLICATION: [u8; 32] = [5; 32];
pub(crate) const RELEASE_TUPLE: [u8; 32] = [6; 32];

pub(crate) fn fixture_authority(
    issuer: &ProviderCredentialRequestAuthorityIssuer,
) -> ProviderCredentialBrokerTransferAuthority {
    let keys = LaunchSecret::from_bytes(LAUNCH_SECRET)
        .unwrap()
        .derive_keys();
    let enrollment = ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
    let binding = ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        uuid(2),
        uuid(3),
        1,
        1,
        uuid(4),
        [7; 32],
        [5; 32],
        [9; 32],
        [10; 32],
        [11; 32],
        [12; 32],
        [13; 32],
        100_000,
        120_000,
    )
    .unwrap();
    let frame = ProtectedCredentialEnrollmentControlFrame::Request(
        enrollment.issue_request(binding.clone(), 1).unwrap(),
    )
    .encode_frame();
    let request = enrollment
        .decode_request(&frame, &binding, 0, 110_000)
        .unwrap();
    let admission_binding = ProtectedCredentialEnrollmentAdmissionBinding::new(
        [3; 32],
        [7; 32],
        [4; 32],
        1,
        [6; 32],
        1,
        [5; 32],
        [9; 32],
        [10; 32],
        uuid(5),
        120_000,
    )
    .unwrap();
    let admission_frame = ProtectedCredentialEnrollmentControlFrame::Admission(
        enrollment
            .issue_admission(&request, admission_binding.clone(), 2)
            .unwrap(),
    )
    .encode_frame();
    let admission = enrollment
        .decode_admission(&admission_frame, &request, &admission_binding, 1, 110_000)
        .unwrap();
    let admission = keys.bind_credential_broker_transfer(admission).unwrap();
    let (_, _, authority) = issuer
        .issue_from_verified_enrollment_with_broker_transfer(request, admission)
        .unwrap();
    authority
}

pub(crate) fn oracle_start_identity(pid: u32) -> [u8; 32] {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let tail = stat.rsplit_once(')').unwrap().1;
    let start_time = tail.split_whitespace().nth(19).unwrap();
    let mut digest = Sha256::new();
    digest.update(b"gocode.provider-credential-writer.start.v1");
    digest.update(pid.to_be_bytes());
    digest.update(start_time.as_bytes());
    digest.finalize().into()
}

pub(crate) fn oracle_image_digest() -> [u8; 32] {
    Sha256::digest(std::fs::read(env!("CARGO_BIN_EXE_runne")).unwrap()).into()
}

pub(crate) fn spawn_writer(handshake: UnixStream) -> std::process::Child {
    // Production layout: STDIN carries the broker control socket (held open
    // by the caller), STDOUT carries the private startup handshake socket.
    let (control_parent, control_child) = UnixStream::pair().expect("control pair");
    // control_parent drops at the end of this function: the writer's loop
    // sees EOF on the control stdin right after the startup exchange.
    let child = Command::new(env!("CARGO_BIN_EXE_runne"))
        .arg(PROVIDER_CREDENTIAL_BROKER_MODE_V1)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(control_child)))
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(handshake)))
        .stderr(Stdio::null())
        .spawn()
        .expect("writer binary");
    drop(control_parent);
    child
}

pub(crate) const fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}

// Keep the transfer authenticator import honest: the fixture never uses the
// writer-side authenticator directly — the writer derives its own.

pub(crate) fn oracle_start_of(pid: u32) -> [u8; 32] {
    oracle_start_identity(pid)
}

pub(crate) fn sign_control_attestation(
    signer: CredentialWriterSessionAttestationSigner,
    writer_start: [u8; 32],
    writer_image: [u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let digest = |bytes: [u8; 32]| CredentialBindingDigest::from_measured(bytes).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let operation_id = CredentialOperationId::from_bytes([31; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    let command = CredentialBrokerCommand::new(
        operation_id,
        attempt,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket: runne_provider::RawCredentialTicket::generate().unwrap(),
        channel_binding: SIGN_CHANNEL,
        binding: digest(SIGN_BINDING),
        command,
    };
    let attested = CredentialIssueTicketBindingV1::from_issue_ticket(&frame).unwrap();
    let encoded_frame = runne_provider::CredentialBrokerFrameCodec::encode(frame).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed();
    let claims = CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            operation_id,
            attempt,
            attested,
            digest(SIGN_BINDING),
            CredentialInstallationOwnerId::from_bytes([2; 32]).unwrap(),
            digest([5; 32]),
            now - 60,
            now + 600,
        )
        .unwrap(),
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest([4; 32]),
            digest([5; 32]),
            digest([6; 32]),
            1,
            1,
            digest(SIGN_TUPLE),
        )
        .unwrap(),
        CredentialWriterSessionProcessClaimsV1::new(
            digest(SIGN_HANDOFF),
            digest(writer_start),
            digest(writer_image),
            digest([27; 32]),
            digest([23; 32]),
            digest([24; 32]),
        )
        .unwrap(),
    );
    let (attestation, _) = signer
        .sign_qualified(claims, 7, [41; 32], [42; 32])
        .unwrap();
    (
        CredentialWriterSessionAttestationV2Codec::encode(&attestation).to_vec(),
        encoded_frame,
    )
}

pub(crate) fn spawn_writer_with_control(
    handshake: UnixStream,
    control: UnixStream,
) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_runne"))
        .arg(PROVIDER_CREDENTIAL_BROKER_MODE_V1)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(control)))
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(handshake)))
        .stderr(Stdio::null())
        .spawn()
        .expect("writer binary")
}
#[allow(unused_imports)]
use CredentialBrokerTransferAuthenticator as _UnusedAuthenticator;

// --- B10: full CONTROL receive through the REAL writer binary ---

pub(crate) const SIGN_CHANNEL: [u8; 32] = [31; 32];
pub(crate) const SIGN_BINDING: [u8; 32] = [3; 32];
pub(crate) const SIGN_TUPLE: [u8; 32] = RELEASE_TUPLE;
pub(crate) const SIGN_HANDOFF: [u8; 32] = [31; 32];
