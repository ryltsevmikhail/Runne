use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialOperationState, ProviderCredentialEnrollmentStore,
};
use zeroize::Zeroizing;

use super::broker_support::{
    RecordingChannel, claim_measurements, fixture, issue_context, pair_offer,
};

#[test]
fn broker_effect_exchange_requires_the_claim_binding_before_possible_effect() {
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
        panic!("broker must issue a ticket frame");
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
    channel.queue_received(Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer: Some(pair_offer(&receipt, binding)),
        })
        .unwrap(),
    ));
    channel.queue_received(Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::NativeEffectObserved {
            operation_id,
            binding,
        })
        .unwrap(),
    ));

    let mut claim = fixture
        .broker
        .claim_ticket_from_channel(
            receipt,
            fixture.continuation,
            7,
            8,
            evidence,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    assert!(claim.take_secret_relay().unwrap().is_some());
    let sent = channel.frames.len();
    assert!(
        fixture
            .broker
            .release_control_only_effect(&claim, operation_id, &fixture.store, &mut channel)
            .is_err()
    );
    assert_eq!(channel.frames.len(), sent);
    fixture
        .broker
        .release_claimed_effect_to_channel(&claim, &mut channel)
        .unwrap();
    assert!(matches!(
        CredentialBrokerFrameCodec::decode(channel.frames.last().unwrap()).unwrap(),
        CredentialBrokerFrame::NativeEffectRelease {
            operation_id: released_operation,
            attempt: released_attempt,
            binding: released_binding,
        } if released_operation == operation_id
            && released_attempt == attempt
            && released_binding == binding
    ));
    let observed = fixture
        .broker
        .observe_effect_from_channel(claim, &fixture.store, &mut channel)
        .unwrap();

    assert_eq!(
        observed.state(),
        CredentialOperationState::NativeEffectObserved
    );
    assert_eq!(
        fixture.store.load_operation(operation_id).unwrap().state(),
        CredentialOperationState::NativeEffectObserved
    );
}

#[test]
fn broker_effect_exchange_rejects_a_substituted_binding_without_state_transition() {
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
        panic!("broker must issue a ticket frame");
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
    channel.queue_received(Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer: Some(pair_offer(&receipt, binding)),
        })
        .unwrap(),
    ));
    channel.queue_received(Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::NativeEffectObserved {
            operation_id,
            binding: CredentialBindingDigest::from_measured([9; 32]).unwrap(),
        })
        .unwrap(),
    ));

    let claim = fixture
        .broker
        .claim_ticket_from_channel(
            receipt,
            fixture.continuation,
            7,
            8,
            evidence,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    assert_eq!(
        fixture
            .broker
            .observe_effect_from_channel(claim, &fixture.store, &mut channel),
        Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
    );
    assert_eq!(
        fixture.store.load_operation(operation_id).unwrap().state(),
        CredentialOperationState::Claimed
    );
}

#[test]
fn control_only_release_accepts_a_claimed_migrate_legacy_without_relay() {
    let fixture = super::broker_support::migrate_fixture();
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
        panic!("broker must issue a ticket frame");
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
    channel.queue_received(Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer: None,
        })
        .unwrap(),
    ));
    channel.queue_received(Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::NativeEffectObserved {
            operation_id,
            binding,
        })
        .unwrap(),
    ));

    let mut claim = fixture
        .broker
        .claim_ticket_from_channel(
            receipt,
            fixture.continuation,
            7,
            8,
            evidence,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    assert!(claim.take_secret_relay().unwrap().is_none());
    fixture
        .broker
        .release_control_only_effect(&claim, operation_id, &fixture.store, &mut channel)
        .unwrap();
    assert!(matches!(
        CredentialBrokerFrameCodec::decode(channel.frames.last().unwrap()).unwrap(),
        CredentialBrokerFrame::NativeEffectRelease {
            operation_id: released_operation,
            attempt: released_attempt,
            binding: released_binding,
        } if released_operation == operation_id
            && released_attempt == attempt
            && released_binding == binding
    ));
}
