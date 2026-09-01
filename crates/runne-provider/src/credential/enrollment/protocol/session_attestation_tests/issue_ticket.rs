use std::io::{Cursor, Read, Write};

use crate::{
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialBrokerTarget, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialIssueTicketBindingV1, CredentialLifecycleRevision, CredentialOperationAction,
    CredentialOperationId, CredentialSecretInputPresence, CredentialTicketAttempt,
    CredentialVersionRef, CredentialWriterAuthorityPair, CredentialWriterCommandScopeV1,
    PendingCredentialIssueTicketV1, ProviderId, WriterIdentityMigrationPhase,
};

use super::support::{command, digest, frame, frame_with_command};

#[test]
fn pending_ticket_reader_consumes_one_issue_ticket_and_leaves_the_next_frame() {
    let first = CredentialBrokerFrameCodec::encode(frame(1, 2, 3, 4, 5, 1)).unwrap();
    let operation_id = CredentialOperationId::from_bytes([9; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(8).unwrap();
    let second = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::ClaimAccepted {
        operation_id,
        attempt,
    })
    .unwrap();
    let mut reader = Cursor::new([first, second].concat());

    let _pending = PendingCredentialIssueTicketV1::read_from(&mut reader).unwrap();

    assert!(matches!(
        CredentialBrokerFrameCodec::read_from(&mut reader),
        Ok(CredentialBrokerFrame::ClaimAccepted {
            operation_id: actual_operation,
            attempt: actual_attempt,
        }) if actual_operation == operation_id && actual_attempt == attempt
    ));
}

#[test]
fn pending_ticket_reader_rejects_a_non_issue_frame() {
    let bytes = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::ClaimAccepted {
        operation_id: CredentialOperationId::from_bytes([9; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(8).unwrap(),
    })
    .unwrap();

    assert!(PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(bytes)).is_err());
}

#[test]
fn retained_ticket_is_the_only_command_source_for_writer_claim() {
    let issued = frame(1, 2, 3, 4, 5, 1);
    let (operation_id, attempt, command) = match &issued {
        CredentialBrokerFrame::IssueTicket {
            operation_id,
            attempt,
            command,
            ..
        } => (*operation_id, *attempt, command.clone()),
        _ => unreachable!(),
    };
    let encoded = CredentialBrokerFrameCodec::encode(issued).unwrap();
    let pending = PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(encoded)).unwrap();
    let accepted = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::ClaimAccepted {
        operation_id,
        attempt,
    })
    .unwrap();
    let mut control = ScriptedControl::new(accepted);
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([4; 32]).unwrap();
    let (issuer, _effects) = CredentialWriterAuthorityPair::new().split();

    let (_authorization, actual_command, actual_binding, _command_kind, pending_opening) = pending
        .claim_on(
            &mut control,
            &issuer,
            &channel,
            CredentialSecretInputPresence::Present,
            CredentialWriterCommandScopeV1::D1_1A,
        )
        .unwrap();

    assert_eq!(actual_command, command);
    assert_eq!(actual_binding, digest(5));
    assert!(pending_opening.is_some());
    assert!(matches!(
        CredentialBrokerFrameCodec::read_from(&mut Cursor::new(control.written)),
        Ok(CredentialBrokerFrame::Claim {
            operation_id: actual_operation,
            attempt: actual_attempt,
            secret_offer: Some(_),
            ..
        }) if actual_operation == operation_id && actual_attempt == attempt
    ));
}

#[test]
fn issue_ticket_binding_matches_independent_sha256_vector() {
    let frame = frame(1, 2, 3, 4, 5, 1);
    let binding = CredentialIssueTicketBindingV1::from_issue_ticket(&frame).unwrap();

    assert_eq!(
        binding.test_only_digest().as_bytes(),
        [
            0xd9, 0xc2, 0x40, 0x0a, 0xfc, 0xdd, 0xe8, 0x12, 0x77, 0xac, 0x62, 0x04, 0xea, 0xfe,
            0xe9, 0xff, 0xf4, 0xed, 0xb7, 0x9a, 0xb1, 0x07, 0x22, 0x93, 0xae, 0x51, 0xde, 0xf9,
            0x4d, 0x91, 0x9c, 0xe3,
        ]
    );
}

#[test]
fn issue_ticket_binding_changes_for_every_structured_field() {
    let baseline = CredentialIssueTicketBindingV1::from_issue_ticket(&frame(1, 2, 3, 4, 5, 1))
        .unwrap()
        .test_only_digest();
    for changed in [
        frame(2, 2, 3, 4, 5, 1),
        frame(1, 3, 3, 4, 5, 1),
        frame(1, 2, 4, 4, 5, 1),
        frame(1, 2, 3, 6, 5, 1),
        frame(1, 2, 3, 4, 6, 1),
        frame(1, 2, 3, 4, 5, 2),
    ] {
        assert_ne!(
            CredentialIssueTicketBindingV1::from_issue_ticket(&changed)
                .unwrap()
                .test_only_digest(),
            baseline
        );
    }
}

#[test]
fn issue_ticket_binding_changes_for_every_canonical_command_field() {
    let baseline = binding(frame(1, 2, 3, 4, 5, 1));
    let operation = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(2).unwrap();
    let openai = ProviderId::new("openai").unwrap();
    let deepseek = ProviderId::new("deepseek").unwrap();
    let commands = [
        CredentialBrokerCommand::new(
            operation,
            attempt,
            deepseek.clone(),
            CredentialOperationAction::Pair,
            CredentialBrokerTarget::Version(CredentialVersionRef::new(deepseek, 1).unwrap()),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            None,
        )
        .unwrap(),
        CredentialBrokerCommand::new(
            operation,
            attempt,
            openai.clone(),
            CredentialOperationAction::Revoke,
            CredentialBrokerTarget::Version(CredentialVersionRef::new(openai.clone(), 1).unwrap()),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            None,
        )
        .unwrap(),
        command(1, 2, 2),
        pair_command(openai.clone(), 2, 1),
        pair_command(openai, 1, 2),
    ];
    for changed in commands {
        assert_ne!(binding(frame_with_command(changed, 3, 4, 5)), baseline);
    }

    let migration_a = migration_command(30);
    let migration_b = migration_command(31);
    assert_ne!(
        binding(frame_with_command(migration_a, 3, 4, 5)),
        binding(frame_with_command(migration_b, 3, 4, 5))
    );
}

#[test]
fn issue_ticket_binding_rejects_non_issue_and_inconsistent_command() {
    let operation = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(2).unwrap();
    let non_issue = CredentialBrokerFrame::ClaimAccepted {
        operation_id: operation,
        attempt,
    };
    let inconsistent = CredentialBrokerFrame::IssueTicket {
        operation_id: operation,
        attempt,
        ticket: crate::RawCredentialTicket::from_decoded([3; 32]).unwrap(),
        channel_binding: [4; 32],
        binding: digest(5),
        command: command(2, 2, 1),
    };

    assert!(CredentialIssueTicketBindingV1::from_issue_ticket(&non_issue).is_err());
    assert!(CredentialIssueTicketBindingV1::from_issue_ticket(&inconsistent).is_err());
}

#[test]
fn issue_ticket_binding_rejects_zero_channel() {
    let command = command(1, 2, 1);
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id: command.operation_id(),
        attempt: command.ticket_attempt(),
        ticket: crate::RawCredentialTicket::from_decoded([3; 32]).unwrap(),
        channel_binding: [0; 32],
        binding: digest(5),
        command,
    };

    assert!(CredentialIssueTicketBindingV1::from_issue_ticket(&frame).is_err());
}

fn binding(frame: CredentialBrokerFrame) -> crate::CredentialBindingDigest {
    CredentialIssueTicketBindingV1::from_issue_ticket(&frame)
        .unwrap()
        .test_only_digest()
}

fn pair_command(provider: ProviderId, revision: u64, fence: u64) -> CredentialBrokerCommand {
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        CredentialTicketAttempt::new(2).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(revision).unwrap(),
        CredentialFence::new(fence).unwrap(),
        None,
    )
    .unwrap()
}

fn migration_command(binding: u8) -> CredentialBrokerCommand {
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        CredentialTicketAttempt::new(2).unwrap(),
        ProviderId::new("openai").unwrap(),
        CredentialOperationAction::WriterIdentityMigrationEffect,
        CredentialBrokerTarget::Migration {
            migration_id: CredentialOperationId::from_bytes([9; 16]).unwrap(),
            phase: WriterIdentityMigrationPhase::OldWriterEffect,
        },
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        Some(digest(binding)),
    )
    .unwrap()
}

struct ScriptedControl {
    readable: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl ScriptedControl {
    fn new(readable: Vec<u8>) -> Self {
        Self {
            readable: Cursor::new(readable),
            written: Vec::new(),
        }
    }
}

impl Read for ScriptedControl {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.readable.read(buffer)
    }
}

impl Write for ScriptedControl {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
