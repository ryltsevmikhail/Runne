use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialFence,
    CredentialInstallationOwnerId, CredentialIssueTicketBindingV1, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialTicketAttempt,
    CredentialVersionRef, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1, ProviderId,
    RawCredentialTicket, daemon_credential_publication,
};

use crate::writer_endpoint_handoff::MacOsUntrustedWriterEndpointHandoffV1;

const CHANNEL: [u8; 32] = [15; 32];
const HANDOFF_BYTES: usize = 160;
const RELEASE_METADATA: &[u8] =
    include_bytes!("../../../runne-api/tests/fixtures/signed_installed_release_v2.json");

pub(super) struct PrefixFixture {
    pub(super) handoff: MacOsUntrustedWriterEndpointHandoffV1,
    pub(super) control: UnixStream,
    pub(super) public_key: [u8; 32],
    pub(super) attestation: [u8; CredentialWriterSessionAttestationCodec::BYTES],
    pub(super) ticket: Vec<u8>,
    pub(super) release: Vec<u8>,
}

impl PrefixFixture {
    pub(super) fn new() -> Self {
        let signer =
            daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate(
                CHANNEL,
            )
            .unwrap();
        let public_key = signer.public_key();
        let (handoff, control) = handoff(public_key);
        let issue = issue_ticket();
        let ticket = CredentialBrokerFrameCodec::encode(issue).unwrap();
        let decoded = CredentialBrokerFrameCodec::decode(&ticket).unwrap();
        let claims = claims(&handoff, &decoded);
        let (attestation, _) = signer.sign(claims).unwrap();
        Self {
            handoff,
            control,
            public_key,
            attestation: CredentialWriterSessionAttestationCodec::encode(&attestation),
            ticket,
            release: release_frame(),
        }
    }

    pub(super) fn prefix(&self) -> Vec<u8> {
        [
            self.attestation.as_slice(),
            self.ticket.as_slice(),
            self.release.as_slice(),
        ]
        .concat()
    }

    pub(super) fn write_prefix(&mut self) {
        self.control.write_all(&self.prefix()).unwrap();
    }

    pub(super) fn observe_with_budget(
        self,
        budget: Duration,
    ) -> Result<
        super::super::MacOsPendingWriterBootstrapTranscriptV1,
        crate::MacOsPackagedWriterObservationError,
    > {
        self.handoff
            .test_only_observe_pending_writer_bootstrap(budget)
    }
}

fn handoff(public_key: [u8; 32]) -> (MacOsUntrustedWriterEndpointHandoffV1, UnixStream) {
    let mut frame = [0_u8; HANDOFF_BYTES];
    frame[..32].copy_from_slice(&CHANNEL);
    frame[96..128].copy_from_slice(&public_key);
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (offered, control) = UnixStream::pair().unwrap();
    let sent = crate::writer_endpoint_handoff::test_only_send_with_descriptors(
        &sender,
        &frame,
        &[offered.as_fd()],
    )
    .unwrap();
    assert_eq!(sent, frame.len());
    sender.shutdown(std::net::Shutdown::Write).unwrap();
    let handoff =
        crate::writer_endpoint_handoff::receive_for_test(&receiver, Duration::from_secs(1))
            .unwrap();
    (handoff, control)
}

fn issue_ticket() -> CredentialBrokerFrame {
    let operation_id = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(2).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket: RawCredentialTicket::generate().unwrap(),
        channel_binding: CHANNEL,
        binding: digest(4),
        command: CredentialBrokerCommand::new(
            operation_id,
            attempt,
            provider.clone(),
            CredentialOperationAction::Pair,
            CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            None,
        )
        .unwrap(),
    }
}

fn claims(
    handoff: &MacOsUntrustedWriterEndpointHandoffV1,
    issue: &CredentialBrokerFrame,
) -> CredentialWriterSessionAttestationClaimsV1 {
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        binding,
        ..
    } = issue
    else {
        unreachable!()
    };
    CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            *operation_id,
            *attempt,
            CredentialIssueTicketBindingV1::from_issue_ticket(issue).unwrap(),
            *binding,
            CredentialInstallationOwnerId::from_bytes([5; 32]).unwrap(),
            digest(6),
            13,
            14,
        )
        .unwrap(),
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest(7),
            digest(8),
            digest(9),
            10,
            11,
            digest(12),
        )
        .unwrap(),
        CredentialWriterSessionProcessClaimsV1::new(
            CredentialBindingDigest::from_measured(*handoff.test_only_digest()).unwrap(),
            digest(17),
            digest(18),
            digest(19),
            digest(20),
            digest(21),
        )
        .unwrap(),
    )
}

fn release_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + RELEASE_METADATA.len());
    frame.extend_from_slice(b"GCRMDV2\0");
    frame.extend_from_slice(&u32::try_from(RELEASE_METADATA.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(RELEASE_METADATA);
    frame
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
