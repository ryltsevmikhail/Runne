use std::cell::Cell;

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    ClaimCredentialOperation, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialTicketAttempt, ProviderCredentialEnrollmentStore,
};
use zeroize::Zeroizing;

use super::broker_support::{
    RecordingChannel, claim_measurements, fixture, issue_context, issue_context_for, pair_offer,
};

#[test]
fn ticket_nonce_is_exactly_256_bits_and_rng_failure_is_closed() {
    let fixture = fixture();
    let context = issue_context(&fixture);
    let mut channel = RecordingChannel::default();
    let fills = Cell::new(0);

    let failure = fixture.broker.issue_ticket_with_test_entropy(
        fixture.operation.clone(),
        fixture.continuation,
        &context,
        60,
        &fixture.store,
        &mut channel,
        |bytes| {
            fills.set(fills.get() + 1);
            assert_eq!(bytes.len(), 32);
            Err(())
        },
    );

    assert_eq!(
        failure,
        Err(ProviderCredentialEnrollmentHostError::Unavailable)
    );
    assert_eq!(fills.get(), 1);
    assert!(channel.frames.is_empty());

    let receipt = fixture
        .broker
        .issue_ticket(
            fixture.operation,
            fixture.continuation,
            &context,
            60,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    assert_eq!(
        receipt.ticket_attempt(),
        CredentialTicketAttempt::new(1).unwrap()
    );
    assert_eq!(channel.frames.len(), 1);
    assert!(channel.frames[0].len() <= CredentialBrokerFrameCodec::MAX_FRAME_BYTES);
    let decoded = CredentialBrokerFrameCodec::decode(&channel.frames[0]).unwrap();
    assert_eq!(
        CredentialBrokerFrameCodec::encode(decoded).unwrap(),
        channel.frames[0]
    );
}

#[test]
fn broker_claim_binding_admits_only_the_exact_issued_ticket() {
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
    let issue = CredentialBrokerFrameCodec::decode(&channel.frames.pop().unwrap()).unwrap();
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
        ..
    } = issue
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
    let claim = Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer: Some(pair_offer(&receipt, binding)),
        })
        .unwrap(),
    );

    let accepted = fixture
        .broker
        .claim_ticket(
            receipt,
            fixture.continuation,
            7,
            8,
            evidence,
            claim,
            &fixture.store,
        )
        .unwrap();

    assert!(matches!(
        CredentialBrokerFrameCodec::decode(accepted.acknowledgement()),
        Ok(CredentialBrokerFrame::ClaimAccepted {
            operation_id: actual,
            attempt: actual_attempt,
        }) if actual == operation_id && actual_attempt == attempt
    ));
    assert!(matches!(
        fixture.store.load_operation(operation_id).unwrap().state(),
        runne_provider::CredentialOperationState::Claimed
    ));
}

#[test]
fn broker_claim_binding_rejects_command_substitution_before_store_claim() {
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
        attempt, ticket, ..
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
    let frame = Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
            operation_id: runne_provider::CredentialOperationId::from_bytes([99; 16]).unwrap(),
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
        fixture
            .store
            .load_operation(fixture.operation.operation_id())
            .unwrap()
            .state(),
        runne_provider::CredentialOperationState::Prepared
    );
}

#[test]
fn broker_reissue_tombstones_the_old_ticket_before_a_new_attempt() {
    let fixture = fixture();
    let mut channel = RecordingChannel::default();
    let reissue_continuation =
        runne_provider::CredentialBindingDigest::from_measured([6; 32]).unwrap();
    let first_context = issue_context_for(&fixture, reissue_continuation);
    let second_context = issue_context(&fixture);
    let first = fixture
        .broker
        .issue_ticket(
            fixture.operation.clone(),
            reissue_continuation,
            &first_context,
            60,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    let CredentialBrokerFrame::IssueTicket {
        attempt, ticket, ..
    } = CredentialBrokerFrameCodec::decode(&channel.frames.remove(0)).unwrap()
    else {
        panic!("broker must issue a ticket frame");
    };
    let second = fixture
        .broker
        .issue_ticket(
            fixture.operation.clone(),
            fixture.continuation,
            &second_context,
            60,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    assert_eq!(
        first.ticket_attempt(),
        CredentialTicketAttempt::new(1).unwrap()
    );
    assert_eq!(
        second.ticket_attempt(),
        CredentialTicketAttempt::new(2).unwrap()
    );
    let draft = ClaimCredentialOperation::new(
        first.clone(),
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
            operation_id: fixture.operation.operation_id(),
            attempt,
            ticket,
            binding,
            secret_offer: Some(pair_offer(&first, binding)),
        })
        .unwrap(),
    );

    channel.queue_received(frame);
    assert!(matches!(
        fixture.broker.claim_ticket_from_channel(
            first,
            fixture.continuation,
            7,
            8,
            evidence,
            &fixture.store,
            &mut channel,
        ),
        Err(ProviderCredentialEnrollmentHostError::Conflict)
    ));
}
