//! Shared inert fixtures; these do not mint production admission.
// `redundant_pub_crate` opt-out: this module is included verbatim by test
// and example crates whose roots are private, so `pub` buys nothing and the
// pedantic doc lints on test-only helpers are pure noise. No weakening.
#![allow(dead_code, unused_imports, clippy::redundant_pub_crate)]
use runne_api::{ProviderCredentialRequestAuthorityIssuer, ProviderCredentialRequestAuthorityPair};
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
use sha2::Digest as _;

pub(super) const LAUNCH_SECRET: [u8; 32] = [7; 32];
pub(super) const CHANNEL: [u8; 32] = [31; 32];
pub(super) const RELEASE_TUPLE: [u8; 32] = [6; 32];
pub(super) const SIGN_CHANNEL: [u8; 32] = [31; 32];
pub(super) const SIGN_BINDING: [u8; 32] = [3; 32];
pub(super) const SIGN_TUPLE: [u8; 32] = RELEASE_TUPLE;
pub(super) const SIGN_HANDOFF: [u8; 32] = [31; 32];

pub(super) fn oracle_start_identity(pid: u32) -> [u8; 32] {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let tail = stat.rsplit_once(')').unwrap().1;
    let start_time = tail.split_whitespace().nth(19).unwrap();
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode.provider-credential-writer.start.v1");
    digest.update(pid.to_be_bytes());
    digest.update(start_time.as_bytes());
    digest.finalize().into()
}

pub(super) fn fixture_authority(
    issuer: &ProviderCredentialRequestAuthorityIssuer,
) -> runne_api::ProviderCredentialBrokerTransferAuthority {
    use runne_api::{
        CredentialBrokerTransferAuthenticator, LaunchSecret,
        ProtectedCredentialEnrollmentAdmissionBinding, ProtectedCredentialEnrollmentAuthenticator,
        ProtectedCredentialEnrollmentControlFrame, ProtectedCredentialEnrollmentRequestBinding,
    };
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
    let _ = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    authority
}

pub(super) const fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}

pub(super) fn digest(bytes: [u8; 32]) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured(bytes).unwrap()
}

pub(super) fn sign_control_attestation_with_tuple(
    signer: CredentialWriterSessionAttestationSigner,
    writer_start: [u8; 32],
    writer_image: [u8; 32],
    tuple: [u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    sign_attestation(signer, writer_start, writer_image, tuple, true)
}

pub(super) fn sign_attestation(
    signer: CredentialWriterSessionAttestationSigner,
    writer_start: [u8; 32],
    writer_image: [u8; 32],
    tuple: [u8; 32],
    qualified: bool,
) -> (Vec<u8>, Vec<u8>) {
    sign_attestation_for_reader(signer, writer_start, writer_image, tuple, qualified, None)
}

#[derive(Clone, Copy)]
pub(super) enum ReaderFault {
    Start,
    Image,
}

pub(super) fn sign_attestation_for_reader(
    signer: CredentialWriterSessionAttestationSigner,
    writer_start: [u8; 32],
    writer_image: [u8; 32],
    tuple: [u8; 32],
    qualified: bool,
    fault: Option<ReaderFault>,
) -> (Vec<u8>, Vec<u8>) {
    let start = if matches!(fault, Some(ReaderFault::Start)) {
        [23; 32]
    } else {
        oracle_start_identity(std::process::id())
    };
    let image = if matches!(fault, Some(ReaderFault::Image)) {
        [24; 32]
    } else {
        sha2::Sha256::digest(std::fs::read("/proc/self/exe").unwrap()).into()
    };
    let (claims, encoded_frame) =
        issue_claims_for_reader(writer_start, writer_image, tuple, start, image);
    if !qualified {
        let (attestation, _) = signer.sign(claims).unwrap();
        return (
            runne_provider::CredentialWriterSessionAttestationCodec::encode(&attestation).to_vec(),
            encoded_frame,
        );
    }
    let (attestation, _) = signer
        .sign_qualified(claims, 7, [41; 32], [42; 32])
        .unwrap();
    (
        CredentialWriterSessionAttestationV2Codec::encode(&attestation).to_vec(),
        encoded_frame,
    )
}

pub(super) fn pair_command() -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    let operation_id = CredentialOperationId::from_bytes([31; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    CredentialBrokerCommand::new(
        operation_id,
        attempt,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

pub(super) fn issue_claims(
    writer_start: [u8; 32],
    writer_image: [u8; 32],
    tuple: [u8; 32],
) -> (CredentialWriterSessionAttestationClaimsV1, Vec<u8>) {
    issue_claims_for_reader(
        writer_start,
        writer_image,
        tuple,
        oracle_start_identity(std::process::id()),
        sha2::Sha256::digest(std::fs::read("/proc/self/exe").unwrap()).into(),
    )
}

fn issue_claims_for_reader(
    writer_start: [u8; 32],
    writer_image: [u8; 32],
    tuple: [u8; 32],
    daemon_start: [u8; 32],
    daemon_image: [u8; 32],
) -> (CredentialWriterSessionAttestationClaimsV1, Vec<u8>) {
    let command = pair_command();
    let operation_id = command.operation_id();
    let attempt = command.ticket_attempt();
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
            digest(tuple),
        )
        .unwrap(),
        CredentialWriterSessionProcessClaimsV1::new(
            digest(SIGN_HANDOFF),
            digest(writer_start),
            digest(writer_image),
            digest([27; 32]),
            digest(daemon_start),
            digest(daemon_image),
        )
        .unwrap(),
    );
    (claims, encoded_frame)
}
