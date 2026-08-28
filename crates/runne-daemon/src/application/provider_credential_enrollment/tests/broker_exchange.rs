use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialBrokerCommand,
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialBrokerTarget,
    CredentialOperationState, ProviderCredentialEnrollmentStore,
};
use zeroize::Zeroizing;

use super::broker_support::{RecordingChannel, claim_measurements, fixture, issue_context};

#[test]
fn broker_claim_exchange_reads_one_claim_and_writes_only_accepted_frame() {
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
        })
        .unwrap(),
    ));

    let _claimed = fixture
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

    assert!(matches!(
        CredentialBrokerFrameCodec::decode(&channel.frames.pop().unwrap()),
        Ok(CredentialBrokerFrame::ClaimAccepted {
            operation_id: actual,
            attempt: actual_attempt,
        }) if actual == operation_id && actual_attempt == attempt
    ));
    assert!(channel.frames.is_empty());
}

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
fn broker_issue_frame_carries_the_exact_durable_command_for_its_ticket_attempt() {
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
        command,
        ..
    } = CredentialBrokerFrameCodec::decode(&channel.frames.pop().unwrap()).unwrap()
    else {
        panic!("broker must issue a ticket frame");
    };
    let expected = CredentialBrokerCommand::new(
        fixture.operation.operation_id(),
        receipt.ticket_attempt(),
        fixture.operation.provider().clone(),
        fixture.operation.action(),
        CredentialBrokerTarget::Version(
            fixture
                .operation
                .allocated_credential_version()
                .unwrap()
                .clone(),
        ),
        fixture.operation.lifecycle_revision(),
        fixture.operation.fence(),
        None,
    )
    .unwrap();

    assert_eq!(operation_id, fixture.operation.operation_id());
    assert_eq!(attempt, receipt.ticket_attempt());
    assert_eq!(command, expected);
}
