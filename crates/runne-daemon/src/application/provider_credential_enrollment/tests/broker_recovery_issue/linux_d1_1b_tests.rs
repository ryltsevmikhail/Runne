use super::*;
use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    BindCredentialReadback, CredentialOperationAction, CredentialOperationSnapshot,
    CredentialOperationState, CredentialReadbackDisposition, ProviderCredentialEnrollmentStore,
};
use zeroize::Zeroizing;

struct ExactAbsenceReader(std::cell::Cell<u8>);

impl crate::application::provider_credential_enrollment::CredentialEnrollmentReadback
    for ExactAbsenceReader
{
    fn observe(
        &self,
        operation: &CredentialOperationSnapshot,
        _: &CredentialBrokerCommand,
    ) -> Result<BindCredentialReadback, ProviderCredentialEnrollmentHostError> {
        assert_eq!(operation.action(), CredentialOperationAction::Revoke);
        self.0.set(self.0.get() + 1);
        BindCredentialReadback::new(
            operation.operation_id(),
            CredentialReadbackDisposition::ExactAbsence,
            CredentialBindingDigest::from_measured([77; 32]).unwrap(),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

#[test]
fn linux_daemon_revoke_lost_writer_ack_recovers_by_exact_absence_once() {
    let (fixture, accepted) = super::fixture::recovery_fixture();
    assert_eq!(
        fixture.operation.action(),
        CredentialOperationAction::Revoke,
        "fixture starts from a committed Revoke fence after an active Pair"
    );
    let context = fixture
        .broker
        .claim_issue_context(
            recovery_measurements(&fixture, [9; 32], [17; 32]),
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
            accepted,
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
        binding,
        ..
    } = CredentialBrokerFrameCodec::decode(&channel.frames[0]).unwrap()
    else {
        panic!("revoke claim ticket expected");
    };
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
    let mut claimed = fixture
        .broker
        .claim_ticket_from_channel(
            receipt,
            fixture.continuation,
            7,
            8,
            recovery_measurements(&fixture, [9; 32], [17; 32]),
            &fixture.store,
            &mut channel,
        )
        .unwrap();
    assert!(claimed.take_secret_relay().unwrap().is_none());
    fixture
        .broker
        .release_control_only_effect(&claimed, operation_id, &fixture.store, &mut channel)
        .unwrap();
    assert_eq!(
        fixture.store.load_operation(operation_id).unwrap().state(),
        CredentialOperationState::Claimed
    );
    let release_count = channel
        .frames
        .iter()
        .filter(|frame| {
            matches!(
                CredentialBrokerFrameCodec::decode(frame),
                Ok(CredentialBrokerFrame::NativeEffectRelease { .. })
            )
        })
        .count();
    assert_eq!(release_count, 1);

    // Model native deletion followed by loss of the writer ACK. Recovery is
    // reader-only: it can commit exact absence but cannot issue another delete.
    let reader = ExactAbsenceReader(std::cell::Cell::new(0));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let gateway = crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway::new(
        &fixture.store,
        &reader,
    );
    gateway.reconcile_online(now).unwrap();
    assert_eq!(reader.0.get(), 1);
    let completed = fixture.store.load_operation(operation_id).unwrap();
    assert_eq!(completed.state(), CredentialOperationState::Completed);
    assert_eq!(
        completed.metadata().readback_disposition(),
        Some(CredentialReadbackDisposition::ExactAbsence)
    );
    let head = fixture
        .store
        .lifecycle_snapshot(completed.provider())
        .unwrap();
    assert!(head.active_version().is_none());
    assert_eq!(head.fence().get(), 3);
    gateway.reconcile_online(now).unwrap();
    assert_eq!(reader.0.get(), 1);
    assert_eq!(
        channel
            .frames
            .iter()
            .filter(|frame| matches!(
                CredentialBrokerFrameCodec::decode(frame),
                Ok(CredentialBrokerFrame::NativeEffectRelease { .. })
            ))
            .count(),
        release_count,
    );
}
