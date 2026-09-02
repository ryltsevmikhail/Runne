use super::super::{
    CredentialMutationGrant, CredentialServiceDisposition, CredentialServiceEpoch,
    CredentialServiceIngressRequest, CredentialServiceProtocolCodec, CredentialServiceReply,
    CredentialServiceRequest,
};
use super::support::{digest, writer_plan_with_grant};
use crate::credential::enrollment::{
    CredentialBrokerFrame, CredentialEnrollmentAuthorityPair, CredentialWriterAuthorityPair,
    protocol::sealed_pair_for_test,
};

#[test]
fn broker_handoff_authenticates_real_claim_before_service_writer_decode() {
    let grant = CredentialMutationGrant::from_wire([91; 32]).unwrap();
    let (command, arm, writer_handoff) = writer_plan_with_grant(grant.digest());
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
}
