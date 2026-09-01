use crate::{CredentialVersionRef, ProviderId};

use super::super::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialDisposition, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, RawCredentialTicket,
};

#[test]
fn credential_enrollment_codec_round_trips_only_known_versioned_frames() {
    let operation_id = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    let ticket = RawCredentialTicket::generate().unwrap();
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
        channel_binding: channel_binding(),
        binding: binding(),
        command: command(operation_id, attempt),
    };
    let bytes = CredentialBrokerFrameCodec::encode(frame).unwrap();
    let decoded = CredentialBrokerFrameCodec::decode(&bytes).unwrap();
    assert_eq!(CredentialBrokerFrameCodec::encode(decoded).unwrap(), bytes);
}

#[test]
fn credential_enrollment_codec_reads_one_exact_frame_from_a_control_stream() {
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id: CredentialOperationId::from_bytes([6; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(3).unwrap(),
        ticket: RawCredentialTicket::generate().unwrap(),
        channel_binding: channel_binding(),
        binding: binding(),
        command: command(
            CredentialOperationId::from_bytes([6; 16]).unwrap(),
            CredentialTicketAttempt::new(3).unwrap(),
        ),
    };
    let encoded = CredentialBrokerFrameCodec::encode(frame).unwrap();
    let decoded = CredentialBrokerFrameCodec::read_from(&mut std::io::Cursor::new(&encoded))
        .expect("one complete control frame");

    assert_eq!(
        CredentialBrokerFrameCodec::encode(decoded).unwrap(),
        encoded
    );
}

#[test]
fn credential_enrollment_codec_writes_one_canonical_frame_to_a_control_stream() {
    let encoded = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::IssueTicket {
        operation_id: CredentialOperationId::from_bytes([7; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(4).unwrap(),
        ticket: RawCredentialTicket::generate().unwrap(),
        channel_binding: channel_binding(),
        binding: binding(),
        command: command(
            CredentialOperationId::from_bytes([7; 16]).unwrap(),
            CredentialTicketAttempt::new(4).unwrap(),
        ),
    })
    .unwrap();
    let frame = CredentialBrokerFrameCodec::decode(&encoded).unwrap();
    let mut output = Vec::new();

    CredentialBrokerFrameCodec::write_to(&mut output, frame).expect("write one control frame");

    assert_eq!(output, encoded);
}

#[test]
fn credential_enrollment_codec_rejects_a_truncated_control_stream_frame() {
    let mut encoded = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::IssueTicket {
        operation_id: CredentialOperationId::from_bytes([8; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(5).unwrap(),
        ticket: RawCredentialTicket::generate().unwrap(),
        channel_binding: channel_binding(),
        binding: binding(),
        command: command(
            CredentialOperationId::from_bytes([8; 16]).unwrap(),
            CredentialTicketAttempt::new(5).unwrap(),
        ),
    })
    .unwrap();
    encoded.pop();

    assert!(CredentialBrokerFrameCodec::read_from(&mut std::io::Cursor::new(encoded)).is_err());
}

#[test]
fn credential_enrollment_codec_rejects_unknown_version_kind_and_oversized_frames() {
    assert_eq!(CredentialBrokerFrameCodec::VERSION, 5);
    for frame in [
        vec![1, 1],
        vec![2, 1],
        vec![CredentialBrokerFrameCodec::VERSION, 0xff],
        vec![0; CredentialBrokerFrameCodec::MAX_FRAME_BYTES + 1],
    ] {
        assert!(CredentialBrokerFrameCodec::decode(&frame).is_err());
    }
}

#[test]
fn credential_enrollment_codec_rejects_short_and_long_raw_tickets() {
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id: CredentialOperationId::from_bytes([2; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(1).unwrap(),
        ticket: RawCredentialTicket::generate().unwrap(),
        channel_binding: channel_binding(),
        binding: binding(),
        command: command(
            CredentialOperationId::from_bytes([2; 16]).unwrap(),
            CredentialTicketAttempt::new(1).unwrap(),
        ),
    };
    let mut bytes = CredentialBrokerFrameCodec::encode(frame).unwrap();
    let mut long = bytes.clone();
    long.push(0);
    bytes.pop();
    assert!(CredentialBrokerFrameCodec::decode(&bytes).is_err());
    assert!(CredentialBrokerFrameCodec::decode(&long).is_err());
}

fn command(
    operation_id: CredentialOperationId,
    attempt: CredentialTicketAttempt,
) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
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

fn binding() -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([42; 32]).unwrap()
}

fn channel_binding() -> [u8; 32] {
    [43; 32]
}

#[test]
fn credential_enrollment_codec_rejects_an_issue_command_for_another_ticket_attempt() {
    let operation_id = CredentialOperationId::from_bytes([9; 16]).unwrap();
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt: CredentialTicketAttempt::new(1).unwrap(),
        ticket: RawCredentialTicket::generate().unwrap(),
        channel_binding: channel_binding(),
        binding: binding(),
        command: command(operation_id, CredentialTicketAttempt::new(2).unwrap()),
    };

    assert!(CredentialBrokerFrameCodec::encode(frame).is_err());
}

#[test]
fn credential_enrollment_codec_carries_claim_results_without_serializing_claims() {
    let operation_id = CredentialOperationId::from_bytes([3; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(2).unwrap();
    let binding = CredentialBindingDigest::from_measured([4; 32]).unwrap();
    for frame in [
        CredentialBrokerFrame::ClaimAccepted {
            operation_id,
            attempt,
        },
        CredentialBrokerFrame::ClaimDenied {
            operation_id,
            attempt,
            disposition: CredentialDisposition::AccessDenied,
        },
        CredentialBrokerFrame::NativeEffectRelease {
            operation_id,
            attempt,
            binding,
        },
        CredentialBrokerFrame::NativeEffectObserved {
            operation_id,
            binding,
        },
    ] {
        let bytes = CredentialBrokerFrameCodec::encode(frame).unwrap();
        assert!(CredentialBrokerFrameCodec::decode(&bytes).is_ok());
    }
}
