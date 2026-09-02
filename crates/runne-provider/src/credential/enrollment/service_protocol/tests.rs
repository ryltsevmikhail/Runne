use super::{
    CredentialServiceDisposition, CredentialServiceEpoch, CredentialServiceIngressRequest,
    CredentialServiceProtocolCodec, CredentialServiceReply, CredentialServiceRequest,
};
use crate::credential::enrollment::CredentialOperationAction;
use zeroize::Zeroizing;

mod constants;
mod read_support;
mod support;
mod writer;
use read_support::{encoded_read, read_requests};
use support::{arm_request_with_correlation, encoded_arm, encoded_arm_security};

#[test]
fn mutation_frame_binds_action_epoch_session_generation_provider_and_version_once() {
    let baseline = encoded_arm_security(1, 2, 3, CredentialOperationAction::Pair, 1, 1);
    let cases = [
        encoded_arm_security(2, 2, 3, CredentialOperationAction::Pair, 1, 1),
        encoded_arm_security(1, 3, 3, CredentialOperationAction::Pair, 1, 1),
        encoded_arm_security(1, 2, 4, CredentialOperationAction::Pair, 1, 1),
        encoded_arm_security(1, 2, 3, CredentialOperationAction::Revoke, 1, 1),
        encoded_arm_security(1, 2, 3, CredentialOperationAction::Pair, 2, 1),
        encoded_arm_security(1, 2, 3, CredentialOperationAction::Pair, 1, 2),
    ];
    for changed in cases {
        assert_ne!(changed, baseline);
        assert!(matches!(
            CredentialServiceProtocolCodec::decode_runtime_request(&changed),
            Ok(CredentialServiceIngressRequest::RuntimeMutationArm(_))
        ));
        assert!(CredentialServiceProtocolCodec::decode_writer_request(&changed).is_err());
    }
}

#[test]
fn mutation_frame_binds_remaining_operation_and_lifecycle_fields() {
    let baseline = encoded_arm(1, 1, 1, 1, 1, 1, 1, 1, 10, 20, 8);
    for changed in [
        encoded_arm(2, 1, 1, 1, 1, 1, 1, 1, 10, 20, 8),
        encoded_arm(1, 2, 1, 1, 1, 1, 1, 1, 10, 20, 8),
        encoded_arm(1, 1, 1, 1, 2, 1, 1, 1, 10, 20, 8),
        encoded_arm(1, 1, 1, 1, 1, 2, 1, 1, 10, 20, 8),
        encoded_arm(1, 1, 1, 1, 1, 1, 2, 1, 10, 20, 8),
        encoded_arm(1, 1, 1, 1, 1, 1, 1, 2, 10, 20, 8),
        encoded_arm(1, 1, 1, 1, 1, 1, 1, 1, 11, 20, 8),
        encoded_arm(1, 1, 1, 1, 1, 1, 1, 1, 10, 21, 8),
        encoded_arm(1, 1, 1, 1, 1, 1, 1, 1, 10, 20, 9),
    ] {
        assert_ne!(changed, baseline);
    }
    let first = arm_request_with_correlation(6);
    let second = arm_request_with_correlation(7);
    let first = CredentialServiceProtocolCodec::encode_request(first).unwrap();
    let second = CredentialServiceProtocolCodec::encode_request(second).unwrap();
    assert_ne!(first.test_bytes(), second.test_bytes());
}

#[test]
fn read_binding_is_independent_and_binds_provider_separately_from_version() {
    let baseline = encoded_read(1, 2, 3, 4, "provider-1", 1, 1, 1, 1, 10, 20, 6, false);
    for changed in [
        encoded_read(2, 2, 3, 4, "provider-1", 1, 1, 1, 1, 10, 20, 6, false),
        encoded_read(1, 3, 3, 4, "provider-1", 1, 1, 1, 1, 10, 20, 6, false),
        encoded_read(1, 2, 4, 4, "provider-1", 1, 1, 1, 1, 10, 20, 6, false),
        encoded_read(1, 2, 3, 5, "provider-1", 1, 1, 1, 1, 10, 20, 6, false),
        encoded_read(1, 2, 3, 4, "provider-2", 1, 1, 1, 1, 10, 20, 6, false),
        encoded_read(1, 2, 3, 4, "provider-1", 2, 1, 1, 1, 10, 20, 6, false),
        encoded_read(1, 2, 3, 4, "provider-1", 1, 2, 1, 1, 10, 20, 6, false),
        encoded_read(1, 2, 3, 4, "provider-1", 1, 1, 2, 1, 10, 20, 6, false),
        encoded_read(1, 2, 3, 4, "provider-1", 1, 1, 1, 2, 10, 20, 6, false),
        encoded_read(1, 2, 3, 4, "provider-1", 1, 1, 1, 1, 11, 20, 6, false),
        encoded_read(1, 2, 3, 4, "provider-1", 1, 1, 1, 1, 10, 21, 6, false),
        encoded_read(1, 2, 3, 4, "provider-1", 1, 1, 1, 1, 10, 20, 7, false),
    ] {
        assert_ne!(changed, baseline);
    }
    assert!(!baseline.windows(32).any(|window| window == [8; 32]));
}

#[test]
fn runtime_reply_rejects_kind_correlation_role_and_variant_substitution() {
    let request = arm_request_with_correlation(6);
    let context = request.context();
    let reply =
        CredentialServiceProtocolCodec::encode_reply(context, CredentialServiceReply::Armed)
            .unwrap();
    assert!(matches!(
        CredentialServiceProtocolCodec::decode_runtime_reply(reply.test_bytes(), context),
        Ok(CredentialServiceReply::Armed)
    ));
    let wrong_correlation = arm_request_with_correlation(7).context();
    assert!(
        CredentialServiceProtocolCodec::decode_runtime_reply(reply.test_bytes(), wrong_correlation)
            .is_err()
    );
    let (metadata, _) = read_requests("provider-1", 1);
    let metadata = CredentialServiceRequest::MetadataReadback(metadata);
    assert!(
        CredentialServiceProtocolCodec::decode_runtime_reply(
            reply.test_bytes(),
            metadata.context()
        )
        .is_err()
    );
    assert!(
        CredentialServiceProtocolCodec::decode_writer_reply(reply.test_bytes(), context).is_err()
    );
    assert!(
        CredentialServiceProtocolCodec::encode_reply(
            context,
            CredentialServiceReply::Metadata { present: true },
        )
        .is_err()
    );
}

#[test]
fn rejection_matrix_is_closed_per_request_kind() {
    let challenge = CredentialServiceRequest::RegistrationChallenge.context();
    let mutation = arm_request_with_correlation(6).context();
    let (metadata, point) = read_requests("provider-1", 1);
    let metadata = CredentialServiceRequest::MetadataReadback(metadata).context();
    let point = CredentialServiceRequest::PointOfUseRead(point).context();
    for context in [challenge, mutation, metadata, point] {
        for disposition in [
            CredentialServiceDisposition::Denied,
            CredentialServiceDisposition::Unavailable,
            CredentialServiceDisposition::Unsupported,
        ] {
            assert!(
                CredentialServiceProtocolCodec::encode_reply(
                    context,
                    CredentialServiceReply::Rejected(disposition),
                )
                .is_ok()
            );
        }
    }
    let session_missing = CredentialServiceDisposition::SessionMissing {
        current_epoch: CredentialServiceEpoch::from_bytes([9; 16]).unwrap(),
    };
    assert!(
        CredentialServiceProtocolCodec::encode_reply(
            challenge,
            CredentialServiceReply::Rejected(session_missing),
        )
        .is_err()
    );
    for context in [mutation, metadata, point] {
        assert!(
            CredentialServiceProtocolCodec::encode_reply(
                context,
                CredentialServiceReply::Rejected(session_missing),
            )
            .is_ok()
        );
        assert!(
            CredentialServiceProtocolCodec::encode_reply(
                context,
                CredentialServiceReply::Rejected(CredentialServiceDisposition::Uncertain),
            )
            .is_err()
        );
    }
    assert!(
        CredentialServiceProtocolCodec::encode_reply(
            challenge,
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Uncertain),
        )
        .is_err()
    );
}

#[test]
fn framing_rejects_magic_version_endianness_exact_eof_and_canonical_duplicate() {
    let request = encoded_arm(1, 1, 1, 1, 1, 1, 1, 1, 10, 20, 8);
    let mut bad_magic = request.clone();
    bad_magic[0] ^= 1;
    let mut bad_version = request.clone();
    bad_version[9] = 2;
    let mut little_endian = request.clone();
    little_endian[10..14].reverse();
    let mut duplicate = request.clone();
    duplicate.insert(16, duplicate[15]);
    let length = (duplicate.len() - 14) as u32;
    duplicate[10..14].copy_from_slice(&length.to_be_bytes());
    for invalid in [bad_magic, bad_version, little_endian, duplicate] {
        assert!(CredentialServiceProtocolCodec::decode_runtime_request(&invalid).is_err());
    }
    assert!(
        CredentialServiceProtocolCodec::decode_runtime_request(&vec![0; 16 * 1024 + 1]).is_err()
    );
}

#[test]
fn general_framing_validator_accepts_exact_sixteen_kibibyte_boundary() {
    let mut frame = vec![0_u8; 16 * 1024];
    frame[..8].copy_from_slice(b"RNCRED01");
    frame[8..10].copy_from_slice(&1_u16.to_be_bytes());
    frame[10..14].copy_from_slice(&((16 * 1024 - 14) as u32).to_be_bytes());
    assert!(super::codec::payload(&frame, frame.len()).is_ok());
}

#[test]
fn runtime_framing_encoder_enforces_inner_ceiling_before_outer_mac() {
    let ceiling = CredentialServiceProtocolCodec::MAX_RUNTIME_PROVIDER_FRAME_BYTES;
    assert!(super::codec::frame(Zeroizing::new(vec![0; ceiling - 14]), ceiling).is_ok());
    assert!(super::codec::frame(Zeroizing::new(vec![0; ceiling - 13]), ceiling).is_err());
}

#[test]
fn challenge_is_payload_free_and_reply_is_desktop_context_bound() {
    let request = CredentialServiceRequest::RegistrationChallenge;
    let context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request).unwrap();
    assert_eq!(frame.test_bytes().len(), 16);
    assert!(matches!(
        CredentialServiceProtocolCodec::decode_desktop_request(frame.test_bytes()),
        Ok(CredentialServiceIngressRequest::RegistrationChallenge)
    ));
    let reply = CredentialServiceProtocolCodec::encode_reply(
        context,
        CredentialServiceReply::RegistrationChallenge {
            epoch: CredentialServiceEpoch::from_bytes([4; 16]).unwrap(),
            nonce: [5; 16],
        },
    )
    .unwrap();
    assert!(
        CredentialServiceProtocolCodec::decode_runtime_reply(reply.test_bytes(), context).is_err()
    );
    assert!(
        CredentialServiceProtocolCodec::decode_desktop_reply(reply.test_bytes(), context).is_ok()
    );
}

#[test]
fn point_of_use_adds_only_trusted_receipt_to_independent_read_binding() {
    let (metadata, point) = read_requests("provider-1", 1);
    let point = CredentialServiceProtocolCodec::encode_request(
        CredentialServiceRequest::PointOfUseRead(point),
    )
    .unwrap();
    let metadata = CredentialServiceProtocolCodec::encode_request(
        CredentialServiceRequest::MetadataReadback(metadata),
    )
    .unwrap();
    assert_ne!(point.test_bytes(), metadata.test_bytes());
}
