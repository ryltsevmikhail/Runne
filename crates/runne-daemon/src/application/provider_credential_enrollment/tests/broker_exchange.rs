use runne_provider::{
    ClaimCredentialOperation, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialSecretOfferCodec,
};
use zeroize::Zeroizing;

use super::broker_support::{
    RecordingChannel, claim_measurements, fixture, issue_context, pair_offer,
};

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
    let offer = pair_offer(&receipt, binding);
    let replay =
        CredentialSecretOfferCodec::decode(&CredentialSecretOfferCodec::encode(&offer)).unwrap();
    let publication_key = channel.publication_public_key();
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

    let mut claimed = fixture
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

    let publication = claimed.take_secret_publication().unwrap().unwrap();
    assert!(
        runne_provider::daemon_credential_publication_test_support::verify(
            publication_key,
            [21; 32],
            replay,
            publication,
        )
        .is_ok()
    );
    assert_eq!(channel.publication_public_key(), publication_key);
    assert!(matches!(
        claimed.take_secret_publication(),
        Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
    ));

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
