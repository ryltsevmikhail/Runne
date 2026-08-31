use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialEnrollmentAuthorityPair, CredentialTicketAttempt,
};

use super::broker_support::{RecordingChannel, claim_measurements_for, fixture};

#[test]
fn issued_ticket_carries_the_exact_precomputed_claim_binding() {
    let fixture = fixture();
    let measurements = claim_measurements_for(&fixture.measurements, fixture.continuation, 8);
    let context = fixture
        .broker
        .claim_issue_context(measurements.clone(), [21; 32], fixture.continuation, 7, 8)
        .unwrap();
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
        ticket,
        channel_binding,
        binding,
        ..
    } = CredentialBrokerFrameCodec::decode(&channel.frames.pop().unwrap()).unwrap()
    else {
        panic!("broker must issue a ticket frame");
    };
    assert_eq!(channel_binding, [21; 32]);
    let draft = ClaimCredentialOperation::new(
        receipt,
        ticket.binding_digest(),
        fixture.continuation,
        ticket.binding_digest(),
        7,
        8,
    )
    .unwrap();

    assert_eq!(
        binding,
        fixture
            .measurements
            .measure_claim_operation(&measurements, &draft)
            .unwrap()
    );
}

#[test]
fn foreign_claim_issue_context_is_rejected_before_ticket_persistence() {
    let fixture = fixture();
    let (_, foreign_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let foreign = claim_measurements_for(&foreign_measurements, fixture.continuation, 8);

    assert!(
        fixture
            .broker
            .claim_issue_context(foreign, [21; 32], fixture.continuation, 7, 8)
            .is_err()
    );
    assert!(
        fixture
            .broker
            .claim_issue_context(
                claim_measurements_for(&fixture.measurements, fixture.continuation, 8),
                [22; 32],
                fixture.continuation,
                7,
                8,
            )
            .is_err()
    );
    let context = fixture
        .broker
        .claim_issue_context(
            claim_measurements_for(&fixture.measurements, fixture.continuation, 8),
            [21; 32],
            fixture.continuation,
            7,
            8,
        )
        .unwrap();
    let mut channel = RecordingChannel::default();
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
}

#[test]
fn substituted_continuation_is_rejected_before_ticket_persistence() {
    let fixture = fixture();
    let context = fixture
        .broker
        .claim_issue_context(
            claim_measurements_for(&fixture.measurements, fixture.continuation, 8),
            [21; 32],
            fixture.continuation,
            7,
            8,
        )
        .unwrap();
    let mut channel = RecordingChannel::default();
    let substituted = CredentialBindingDigest::from_measured([99; 32]).unwrap();

    assert!(
        fixture
            .broker
            .issue_ticket(
                fixture.operation.clone(),
                substituted,
                &context,
                60,
                &fixture.store,
                &mut channel,
            )
            .is_err()
    );
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
}
