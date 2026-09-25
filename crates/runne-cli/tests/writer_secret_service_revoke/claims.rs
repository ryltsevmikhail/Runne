use runne_provider::{CredentialBrokerFrame as Frame, CredentialBrokerFrameCodec as Codec};
use sha2::Digest as _;

use super::super::writer_support;

pub(super) fn revoke_command(version: u64) -> runne_provider::CredentialBrokerCommand {
    use runne_provider::*;
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([41; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Revoke,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, version).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

pub(super) fn issue_ticket(command: &runne_provider::CredentialBrokerCommand) -> Vec<u8> {
    Codec::encode(Frame::IssueTicket {
        operation_id: command.operation_id(),
        attempt: command.ticket_attempt(),
        ticket: runne_provider::RawCredentialTicket::generate().unwrap(),
        channel_binding: writer_support::SIGN_CHANNEL,
        binding: writer_support::digest(writer_support::SIGN_BINDING),
        command: command.clone(),
    })
    .unwrap()
}

pub(super) fn claims(
    issue: &[u8],
    start: [u8; 32],
    image: [u8; 32],
) -> runne_provider::CredentialWriterSessionAttestationClaimsV1 {
    use runne_provider::*;
    let Frame::IssueTicket {
        operation_id,
        attempt,
        ..
    } = Codec::read_from(&mut &issue[..]).unwrap()
    else {
        unreachable!()
    };
    let attested = CredentialIssueTicketBindingV1::from_issue_ticket(
        &Codec::read_from(&mut &issue[..]).unwrap(),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .cast_signed();
    CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            operation_id,
            attempt,
            attested,
            writer_support::digest(writer_support::SIGN_BINDING),
            CredentialInstallationOwnerId::from_bytes([2; 32]).unwrap(),
            writer_support::digest([5; 32]),
            now - 60,
            now + 600,
        )
        .unwrap(),
        CredentialWriterSessionRuntimeClaimsV1::new(
            writer_support::digest([4; 32]),
            writer_support::digest([5; 32]),
            writer_support::digest([6; 32]),
            1,
            1,
            writer_support::digest(super::support::RELEASE_TUPLE),
        )
        .unwrap(),
        CredentialWriterSessionProcessClaimsV1::new(
            writer_support::digest(writer_support::SIGN_HANDOFF),
            writer_support::digest(start),
            writer_support::digest(image),
            writer_support::digest([27; 32]),
            writer_support::digest(writer_support::oracle_start_identity(std::process::id())),
            writer_support::digest(
                sha2::Sha256::digest(std::fs::read("/proc/self/exe").unwrap()).into(),
            ),
        )
        .unwrap(),
    )
}
