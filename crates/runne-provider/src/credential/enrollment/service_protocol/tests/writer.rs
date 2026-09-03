use super::super::{
    CredentialMaterial, CredentialMutationGrant, CredentialServiceDisposition,
    CredentialServiceEpoch, CredentialServiceIngressRequest, CredentialServiceProtocolCodec,
    CredentialServiceReply, CredentialServiceRequest, CredentialWriterBrokerHandoffFrame,
};
use super::support::{digest, writer_plan_for_action_with_grant, writer_plan_with_grant};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialEnrollmentAuthorityPair,
    CredentialOperationAction, CredentialWriterAuthorityPair, protocol::sealed_pair_for_test,
};
use std::cell::Cell;

#[test]
fn broker_handoff_authenticates_real_claim_before_service_writer_decode() {
    let grant = CredentialMutationGrant::from_wire([91; 32]).unwrap();
    let (command, arm, writer_handoff) = writer_plan_with_grant(grant.digest());
    assert_eq!(arm.installation_owner(), [5; 32]);
    let arm_context = CredentialServiceRequest::RuntimeMutationArm(arm).context();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([7; 32]).unwrap();
    let claim_binding = digest(9);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let sealed = sealed_pair_for_test(&command, claim_binding, &channel, vec![92; 4096]).unwrap();
    let pending = issuer.issue_pending_claim(&command, claim_binding, &channel);
    let authorization = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            claim_binding,
            &channel,
        )
        .unwrap();
    let handoff =
        CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer_handoff, grant)
            .unwrap();
    let writer = CredentialServiceProtocolCodec::decode_authenticated_writer_broker_handoff(
        handoff.test_bytes(),
        authorization,
        &effects,
        &channel,
        claim_binding,
        sealed.pending,
        sealed.envelope,
    )
    .unwrap();
    let request = CredentialServiceRequest::WriterConsume(writer);
    let context = request.context();
    assert_eq!(context.epoch, arm_context.epoch);
    assert_eq!(context.sequence, arm_context.sequence);
    assert_eq!(context.correlation, arm_context.correlation);
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
    assert!(
        CredentialServiceProtocolCodec::encode_reply(
            context,
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Uncertain),
        )
        .is_ok()
    );
    let request = CredentialServiceProtocolCodec::encode_request(request).unwrap();
    assert!(
        request
            .test_bytes()
            .windows(32)
            .any(|window| window == [91; 32])
    );
    let error = CredentialServiceProtocolCodec::encode_reply(
        context,
        CredentialServiceReply::Rejected(CredentialServiceDisposition::SessionMissing {
            current_epoch: CredentialServiceEpoch::from_bytes([9; 16]).unwrap(),
        }),
    )
    .unwrap();
    assert!(
        !error
            .test_bytes()
            .windows(32)
            .any(|window| window == [91; 32])
    );
    assert!(
        !error
            .test_bytes()
            .windows(32)
            .any(|window| window == [92; 32])
    );
    let decoded =
        CredentialServiceProtocolCodec::decode_writer_reply(error.test_bytes(), context).unwrap();
    assert!(decoded.into_reconciliation().is_ok());
    assert!(matches!(
        CredentialServiceProtocolCodec::decode_writer_request(request.test_bytes()),
        Ok(CredentialServiceIngressRequest::WriterConsume(_))
    ));
    assert_eq!(&request.test_bytes()[8..10], &2_u16.to_be_bytes());
    let mut legacy = request.test_bytes().to_vec();
    legacy.drain(32..64);
    legacy[8..10].copy_from_slice(&1_u16.to_be_bytes());
    let length = u32::try_from(legacy.len() - 14).unwrap();
    legacy[10..14].copy_from_slice(&length.to_be_bytes());
    assert!(CredentialServiceProtocolCodec::decode_writer_request(&legacy).is_err());
}

#[test]
fn writer_handoff_stream_reader_consumes_exactly_one_bounded_frame() {
    let grant = CredentialMutationGrant::from_wire([91; 32]).unwrap();
    let (_, _, writer_handoff) = writer_plan_with_grant(grant.digest());
    let encoded =
        CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer_handoff, grant)
            .unwrap()
            .into_transport_bytes();
    let frame_len = encoded.len();
    let mut stream = std::io::Cursor::new(encoded.to_vec());
    stream.get_mut().extend_from_slice(b"NEXT");

    let decoded = CredentialWriterBrokerHandoffFrame::read_from(&mut stream).unwrap();

    assert_eq!(stream.position(), u64::try_from(frame_len).unwrap());
    decoded
        .send::<()>(|bytes| {
            assert_eq!(&bytes[..8], b"RNCRED01");
            assert_eq!(&bytes[8..10], &2_u16.to_be_bytes());
            Ok(())
        })
        .unwrap();
}

#[test]
fn revoke_handoff_authenticates_without_inventing_credential_material() {
    let grant = CredentialMutationGrant::from_wire([81; 32]).unwrap();
    let (command, _, writer_handoff) =
        writer_plan_for_action_with_grant(CredentialOperationAction::Revoke, grant.digest());
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([7; 32]).unwrap();
    let binding = CredentialBindingDigest::from_measured([9; 32]).unwrap();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, binding, &channel);
    let authorization = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            &channel,
        )
        .unwrap();
    let handoff =
        CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer_handoff, grant)
            .unwrap()
            .into_transport_bytes();

    let request = CredentialServiceProtocolCodec::decode_authenticated_writer_control_handoff(
        &handoff,
        authorization,
        &effects,
        &channel,
        binding,
    )
    .unwrap();
    let encoded = CredentialServiceProtocolCodec::encode_request(
        CredentialServiceRequest::WriterConsume(request),
    )
    .unwrap();

    assert!(matches!(
        CredentialServiceProtocolCodec::decode_writer_request(encoded.test_bytes()),
        Ok(CredentialServiceIngressRequest::WriterConsume(_))
    ));
}

#[test]
fn legacy_migration_handoff_reads_material_only_after_exact_claim_authentication() {
    let grant = CredentialMutationGrant::from_wire([71; 32]).unwrap();
    let (command, _, writer_handoff) =
        writer_plan_for_action_with_grant(CredentialOperationAction::MigrateLegacy, grant.digest());
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([7; 32]).unwrap();
    let binding = CredentialBindingDigest::from_measured([9; 32]).unwrap();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, binding, &channel);
    let authorization = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            &channel,
        )
        .unwrap();
    let handoff =
        CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer_handoff, grant)
            .unwrap()
            .into_transport_bytes();
    let reads = Cell::new(0);

    let request = CredentialServiceProtocolCodec::decode_authenticated_writer_legacy_handoff(
        &handoff,
        authorization,
        &effects,
        &channel,
        binding,
        |_| {
            reads.set(reads.get() + 1);
            CredentialMaterial::from_bytes(vec![72; 32])
        },
    )
    .unwrap();

    assert_eq!(reads.get(), 1);
    let encoded = CredentialServiceProtocolCodec::encode_request(
        CredentialServiceRequest::WriterConsume(request),
    )
    .unwrap();
    assert!(matches!(
        CredentialServiceProtocolCodec::decode_writer_request(encoded.test_bytes()),
        Ok(CredentialServiceIngressRequest::WriterConsume(_))
    ));
}

#[test]
fn legacy_migration_handoff_rejects_mismatched_claim_before_reading_material() {
    let grant = CredentialMutationGrant::from_wire([61; 32]).unwrap();
    let (command, _, writer_handoff) =
        writer_plan_for_action_with_grant(CredentialOperationAction::MigrateLegacy, grant.digest());
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([7; 32]).unwrap();
    let binding = CredentialBindingDigest::from_measured([9; 32]).unwrap();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, binding, &channel);
    let authorization = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            &channel,
        )
        .unwrap();
    let handoff =
        CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer_handoff, grant)
            .unwrap()
            .into_transport_bytes();
    let reads = Cell::new(0);

    let result = CredentialServiceProtocolCodec::decode_authenticated_writer_legacy_handoff(
        &handoff,
        authorization,
        &effects,
        &channel,
        CredentialBindingDigest::from_measured([10; 32]).unwrap(),
        |_| {
            reads.set(reads.get() + 1);
            CredentialMaterial::from_bytes(vec![62; 32])
        },
    );

    assert!(result.is_err());
    assert_eq!(reads.get(), 0);
}
