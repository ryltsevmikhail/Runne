use ring::signature::{Ed25519KeyPair, KeyPair as _};

use crate::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerTarget, CredentialFence, CredentialIssueTicketBindingV1,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, CredentialVersionRef, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionProcessClaimsV1, CredentialWriterSessionRuntimeClaimsV1,
    CredentialWriterSessionTicketClaimsV1, ProviderId, RawCredentialTicket,
};

pub(super) const SEED: [u8; 32] = [42; 32];
pub(super) const EXPECTED_PUBLIC_KEY: [u8; 32] = [
    0x19, 0x7f, 0x6b, 0x23, 0xe1, 0x6c, 0x85, 0x32, 0xc6, 0xab, 0xc8, 0x38, 0xfa, 0xcd, 0x5e, 0xa7,
    0x89, 0xbe, 0x0c, 0x76, 0xb2, 0x92, 0x03, 0x34, 0x03, 0x9b, 0xfa, 0x8b, 0x3d, 0x36, 0x8d, 0x61,
];
pub(super) const EXPECTED_SIGNATURE: [u8; 64] = [
    0xb3, 0x68, 0x82, 0x04, 0xed, 0xb6, 0x0a, 0x3d, 0xa7, 0x21, 0x6a, 0xd9, 0x43, 0x77, 0x02, 0x54,
    0x76, 0x68, 0x51, 0x12, 0xec, 0xac, 0x5c, 0x5c, 0x32, 0x4d, 0x49, 0x96, 0xa9, 0x7f, 0xc9, 0x1f,
    0x98, 0xc7, 0xfc, 0x32, 0x4c, 0x7f, 0x5a, 0xa4, 0x0a, 0x52, 0x08, 0x88, 0xec, 0x2c, 0x98, 0x3b,
    0x6a, 0xdf, 0x14, 0xf3, 0x91, 0xb0, 0xf5, 0x57, 0xbb, 0x59, 0x20, 0x95, 0x3d, 0x2d, 0x84, 0x0d,
];
pub(super) const EXPECTED_ATTESTATION_DIGEST: [u8; 32] = [
    0x7a, 0xa9, 0xd3, 0xf5, 0xdc, 0x1d, 0x41, 0x9f, 0xbc, 0x55, 0xba, 0x1b, 0xb2, 0xfe, 0x91, 0x62,
    0x89, 0x69, 0xd6, 0x9f, 0x64, 0xf3, 0xd1, 0xf3, 0xae, 0x50, 0xef, 0xd8, 0x80, 0x8c, 0x8a, 0x8d,
];

pub(super) fn kat_bytes() -> [u8; 641] {
    let mut bytes = [0; 641];
    bytes[0] = 1;
    bytes[1..17].fill(1);
    bytes[17..25].copy_from_slice(&2_u64.to_be_bytes());
    for (range, value) in [
        (25..57, 3),
        (57..89, 4),
        (89..121, 5),
        (121..153, 6),
        (153..185, 7),
        (185..217, 8),
        (217..249, 9),
    ] {
        bytes[range].fill(value);
    }
    bytes[249..257].copy_from_slice(&10_u64.to_be_bytes());
    bytes[257..265].copy_from_slice(&11_u64.to_be_bytes());
    bytes[265..297].fill(12);
    bytes[297..305].copy_from_slice(&13_i64.to_be_bytes());
    bytes[305..313].copy_from_slice(&14_i64.to_be_bytes());
    bytes[313..345].fill(15);
    bytes[345..377].copy_from_slice(&EXPECTED_PUBLIC_KEY);
    for (range, value) in [
        (377..409, 16),
        (409..441, 17),
        (441..473, 18),
        (473..505, 19),
        (505..537, 20),
        (537..569, 21),
    ] {
        bytes[range].fill(value);
    }
    bytes[569..577].copy_from_slice(&0_u64.to_be_bytes());
    bytes[577..].copy_from_slice(&EXPECTED_SIGNATURE);
    bytes
}

pub(super) fn resign(bytes: &mut [u8; 641], seed: [u8; 32], domain: &[u8]) -> [u8; 32] {
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public_key = key.public_key().as_ref().try_into().unwrap();
    let message = [domain, &bytes[..577]].concat();
    bytes[577..].copy_from_slice(key.sign(&message).as_ref());
    public_key
}

pub(super) fn frame(
    operation: u8,
    attempt: u64,
    ticket: u8,
    channel: u8,
    claim: u8,
    version: u64,
) -> CredentialBrokerFrame {
    let command = command(operation, attempt, version);
    frame_with_command(command, ticket, channel, claim)
}

pub(super) fn frame_with_command(
    command: CredentialBrokerCommand,
    ticket: u8,
    channel: u8,
    claim: u8,
) -> CredentialBrokerFrame {
    CredentialBrokerFrame::IssueTicket {
        operation_id: command.operation_id(),
        attempt: command.ticket_attempt(),
        ticket: RawCredentialTicket::from_decoded([ticket; 32]).unwrap(),
        channel_binding: [channel; 32],
        binding: digest(claim),
        command,
    }
}

pub(super) fn command(operation: u8, attempt: u64, version: u64) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        CredentialTicketAttempt::new(attempt).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, version).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

pub(super) fn claims(frame: &CredentialBrokerFrame) -> CredentialWriterSessionAttestationClaimsV1 {
    let issue = CredentialIssueTicketBindingV1::from_issue_ticket(frame).unwrap();
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        binding,
        ..
    } = frame
    else {
        unreachable!()
    };
    CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            *operation_id,
            *attempt,
            issue,
            *binding,
            crate::CredentialInstallationOwnerId::from_bytes([5; 32]).unwrap(),
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
            digest(16),
            digest(17),
            digest(18),
            digest(19),
            digest(20),
            digest(21),
        )
        .unwrap(),
    )
}

pub(super) fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
