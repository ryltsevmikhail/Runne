use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialOperationState, ProviderCredentialEnrollmentStore,
};
use zeroize::Zeroizing;

use super::broker_support::{RecordingChannel, claim_measurements, fixture, issue_context};

#[test]
fn pair_claim_without_offer_is_rejected_before_the_durable_cas() {
    let fixture = fixture();
    let context = issue_context(&fixture);
    let mut channel = RecordingChannel::default();
    let receipt = fixture
        .broker
        .issue_ticket(
            fixture.operation.clone(),
            fixture.continuation,
            &context,
            60,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
        ..
    } = CredentialBrokerFrameCodec::decode(&channel.frames.pop().unwrap()).unwrap()
    else {
        panic!()
    };
    let draft = ClaimCredentialOperation::new(
        receipt.clone(),
        ticket.binding_digest(),
        fixture.continuation,
        ticket.binding_digest(),
        7,
        8,
    )
    .unwrap();
    let evidence = claim_measurements(&fixture.measurements, &draft);
    let binding = fixture
        .measurements
        .measure_claim_operation(&evidence, &draft)
        .unwrap();
    let frame = Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer: None,
        })
        .unwrap(),
    );

    assert!(matches!(
        fixture.broker.claim_ticket(
            receipt,
            fixture.continuation,
            7,
            8,
            evidence,
            frame,
            &fixture.store,
        ),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
    assert_eq!(
        fixture.store.load_operation(operation_id).unwrap().state(),
        CredentialOperationState::Prepared
    );
}

#[test]
fn foreign_channel_binding_is_rejected_before_receive_or_durable_cas() {
    let fixture = fixture();
    let context = issue_context(&fixture);
    let mut issue_channel = RecordingChannel::default();
    let receipt = fixture
        .broker
        .issue_ticket(
            fixture.operation.clone(),
            fixture.continuation,
            &context,
            60,
            &fixture.store,
            &mut issue_channel,
        )
        .unwrap();
    let draft = ClaimCredentialOperation::new(
        receipt.clone(),
        runne_provider::RawCredentialTicket::generate()
            .unwrap()
            .binding_digest(),
        fixture.continuation,
        CredentialBindingDigest::from_measured([90; 32]).unwrap(),
        7,
        8,
    )
    .unwrap();
    let evidence = claim_measurements(&fixture.measurements, &draft);
    let mut foreign = RecordingChannel::with_channel_binding([91; 32]);

    assert!(matches!(
        fixture.broker.claim_ticket_from_channel(
            receipt,
            fixture.continuation,
            7,
            8,
            evidence,
            &fixture.store,
            &mut foreign,
        ),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
    assert!(foreign.frames.is_empty());
    assert_eq!(foreign.receive_calls, 0);
    assert_eq!(
        fixture
            .store
            .load_operation(fixture.operation.operation_id())
            .unwrap()
            .state(),
        CredentialOperationState::Prepared
    );
}

#[test]
fn ack_send_failure_returns_no_effect_or_publication() {
    let fixture = fixture();
    let context = issue_context(&fixture);
    let mut channel = RecordingChannel::default();
    let receipt = fixture
        .broker
        .issue_ticket(
            fixture.operation.clone(),
            fixture.continuation,
            &context,
            60,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
        ..
    } = CredentialBrokerFrameCodec::decode(&channel.frames.pop().unwrap()).unwrap()
    else {
        panic!()
    };
    let draft = ClaimCredentialOperation::new(
        receipt.clone(),
        ticket.binding_digest(),
        fixture.continuation,
        ticket.binding_digest(),
        7,
        8,
    )
    .unwrap();
    let evidence = claim_measurements(&fixture.measurements, &draft);
    let binding = fixture
        .measurements
        .measure_claim_operation(&evidence, &draft)
        .unwrap();
    let command =
        runne_provider::CredentialBrokerCommand::from_operation(receipt.operation(), attempt)
            .unwrap();
    let offer = runne_provider::CredentialSecretClaimOffer::prepare(&command, binding)
        .unwrap()
        .0;
    channel.queue_received(Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer: Some(offer),
        })
        .unwrap(),
    ));
    channel.fail_next_send();

    assert!(matches!(
        fixture.broker.claim_ticket_from_channel(
            receipt,
            fixture.continuation,
            7,
            8,
            evidence,
            &fixture.store,
            &mut channel,
        ),
        Err(ProviderCredentialEnrollmentHostError::Unavailable)
    ));
    assert_eq!(channel.sign_invocations, 0);
    assert_eq!(
        fixture.store.load_operation(operation_id).unwrap().state(),
        CredentialOperationState::Claimed
    );
}

#[test]
fn nonpair_actions_reject_extra_offers_before_store_claim() {
    assert!(!super::super::broker::secret_offer_matches_action(
        runne_provider::CredentialOperationAction::Revoke,
        true,
        true,
    ));
    assert!(!super::super::broker::secret_offer_matches_action(
        runne_provider::CredentialOperationAction::Pair,
        false,
        false,
    ));
}
