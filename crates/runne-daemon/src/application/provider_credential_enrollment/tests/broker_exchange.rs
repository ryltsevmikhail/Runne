use runne_provider::{ClaimCredentialOperation, CredentialBrokerFrame, CredentialBrokerFrameCodec};
use zeroize::Zeroizing;

use super::broker_support::{RecordingChannel, claim_measurements, fixture};

#[test]
fn broker_claim_exchange_reads_one_claim_and_writes_only_accepted_frame() {
    let fixture = fixture();
    let mut channel = RecordingChannel::default();
    let receipt = fixture
        .broker
        .issue_ticket(
            fixture.operation.clone(),
            fixture.continuation,
            60,
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
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

    fixture
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
