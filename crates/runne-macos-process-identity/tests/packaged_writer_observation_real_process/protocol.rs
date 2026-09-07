use std::io::IoSlice;
use std::mem::size_of;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;

#[cfg(any(test, feature = "test-support"))]
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialFence,
    CredentialInstallationOwnerId, CredentialIssueTicketBindingV1, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialTicketAttempt,
    CredentialVersionRef, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1, ProviderId,
    RawCredentialTicket, daemon_credential_publication::CredentialWriterSessionAttestationSigner,
};
#[cfg(any(test, feature = "test-support"))]
use sha2::{Digest as _, Sha256};

#[cfg(any(test, feature = "test-support"))]
use super::release::ReleaseFixture;

pub const CHANNEL: [u8; 32] = [0x41; 32];
const HANDOFF_DOMAIN: &[u8] = b"GOCODE_WRITER_ENDPOINT_HANDOFF_V1\0";

pub fn handoff_frame(public_key: [u8; 32]) -> [u8; 160] {
    let mut frame = [0_u8; 160];
    frame[..32].copy_from_slice(&CHANNEL);
    frame[32..64].fill(0x42);
    frame[64..96].fill(0x43);
    frame[96..128].copy_from_slice(&public_key);
    frame[128..].fill(0x44);
    frame
}

#[cfg(any(test, feature = "test-support"))]
pub fn bootstrap_prefix(
    handoff: &[u8; 160],
    signer: CredentialWriterSessionAttestationSigner,
    release: &ReleaseFixture,
    writer_start: [u8; 32],
    daemon_start: [u8; 32],
) -> Vec<u8> {
    let issue = issue_ticket();
    let claims = claims(handoff, &issue, release, writer_start, daemon_start);
    let (attestation, _publication) = signer.sign(claims).expect("sign exact session facts");
    let ticket = CredentialBrokerFrameCodec::encode(issue).expect("encode issue ticket");
    [
        CredentialWriterSessionAttestationCodec::encode(&attestation).as_slice(),
        ticket.as_slice(),
        release.frame().as_slice(),
    ]
    .concat()
}

#[cfg(any(test, feature = "test-support"))]
fn issue_ticket() -> CredentialBrokerFrame {
    let operation_id = CredentialOperationId::from_bytes([1; 16]).expect("operation id");
    let attempt = CredentialTicketAttempt::new(2).expect("attempt");
    let provider = ProviderId::new("openai").expect("provider");
    CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket: RawCredentialTicket::generate().expect("ticket entropy"),
        channel_binding: CHANNEL,
        binding: digest([4; 32]),
        command: CredentialBrokerCommand::new(
            operation_id,
            attempt,
            provider.clone(),
            CredentialOperationAction::Pair,
            CredentialBrokerTarget::Version(
                CredentialVersionRef::new(provider, 1).expect("provider version"),
            ),
            CredentialLifecycleRevision::new(1).expect("lifecycle revision"),
            CredentialFence::new(1).expect("fence"),
            None,
        )
        .expect("issue command"),
    }
}

#[cfg(any(test, feature = "test-support"))]
fn claims(
    handoff: &[u8; 160],
    issue: &CredentialBrokerFrame,
    release: &ReleaseFixture,
    writer_start: [u8; 32],
    daemon_start: [u8; 32],
) -> CredentialWriterSessionAttestationClaimsV1 {
    let issued_at = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock after epoch")
            .as_secs(),
    )
    .expect("test clock fits signed seconds");
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        binding,
        ..
    } = issue
    else {
        unreachable!("fixture creates IssueTicket")
    };
    CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            *operation_id,
            *attempt,
            CredentialIssueTicketBindingV1::from_issue_ticket(issue)
                .expect("bind exact issue ticket"),
            *binding,
            CredentialInstallationOwnerId::from_bytes([5; 32]).expect("owner"),
            digest([6; 32]),
            issued_at,
            issued_at + 60,
        )
        .expect("ticket claims"),
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest([7; 32]),
            digest([8; 32]),
            digest([9; 32]),
            10,
            11,
            digest(release.binding()),
        )
        .expect("runtime claims"),
        CredentialWriterSessionProcessClaimsV1::new(
            digest(handoff_digest(handoff)),
            digest(writer_start),
            digest(release.writer_digest()),
            digest([0x45; 32]),
            digest(daemon_start),
            digest(release.daemon_digest()),
        )
        .expect("process claims"),
    )
}

#[cfg(any(test, feature = "test-support"))]
fn handoff_digest(frame: &[u8; 160]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(HANDOFF_DOMAIN);
    digest.update(frame);
    digest.finalize().into()
}

#[cfg(any(test, feature = "test-support"))]
fn digest(value: [u8; 32]) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured(value).expect("nonzero fixture digest")
}

pub fn send_handoff(transport: &UnixStream, control: &UnixStream, frame: &[u8; 160]) {
    let sent = send_right(transport, &IoSlice::new(frame), control.as_raw_fd());
    assert_eq!(sent, frame.len());
}

fn send_right(transport: &UnixStream, bytes: &IoSlice<'_>, descriptor: libc::c_int) -> usize {
    #[repr(C, align(16))]
    struct AlignedControl([u8; 64]);

    let mut control = AlignedControl([0; 64]);
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as _) } as _;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!header.is_null());
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as _) as _;
        libc::CMSG_DATA(header)
            .cast::<libc::c_int>()
            .write(descriptor);
    }
    let sent = unsafe { libc::sendmsg(transport.as_raw_fd(), &message, 0) };
    assert!(
        sent >= 0,
        "sendmsg failed: {}",
        std::io::Error::last_os_error()
    );
    usize::try_from(sent).expect("nonnegative send length")
}
