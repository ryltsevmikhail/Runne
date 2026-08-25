use super::super::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialDisposition, CredentialOperationId, CredentialTicketAttempt, RawCredentialTicket,
};

#[test]
fn credential_enrollment_codec_round_trips_only_known_versioned_frames() {
    let operation_id = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    let ticket = RawCredentialTicket::from_os_random([2; 32]).unwrap();
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
    };
    let bytes = CredentialBrokerFrameCodec::encode(frame).unwrap();
    let decoded = CredentialBrokerFrameCodec::decode(&bytes).unwrap();
    assert_eq!(CredentialBrokerFrameCodec::encode(decoded).unwrap(), bytes);
}

#[test]
fn credential_enrollment_codec_rejects_unknown_version_kind_and_oversized_frames() {
    for frame in [
        vec![2, 1],
        vec![CredentialBrokerFrameCodec::VERSION, 0xff],
        vec![0; CredentialBrokerFrameCodec::MAX_FRAME_BYTES + 1],
    ] {
        assert!(CredentialBrokerFrameCodec::decode(&frame).is_err());
    }
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
        CredentialBrokerFrame::NativeEffectObserved {
            operation_id,
            binding,
        },
    ] {
        let bytes = CredentialBrokerFrameCodec::encode(frame).unwrap();
        assert!(CredentialBrokerFrameCodec::decode(&bytes).is_ok());
    }
}
