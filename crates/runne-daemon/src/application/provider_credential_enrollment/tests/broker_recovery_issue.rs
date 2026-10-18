use super::broker_support::*;
#[cfg(target_os = "linux")]
#[path = "broker_recovery_issue/linux_d1_1b_tests.rs"]
mod linux_d1_1b_tests;
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::*;

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

mod deterministic_clock;
pub(crate) mod fixture;
#[cfg(unix)]
mod reservation;
use fixture::recovery_fixture;

#[test]
fn broker_recovery_issue_uses_sealed_attachment_and_bounded_ticket() {
    let (f, accepted) = recovery_fixture();
    let expiry = accepted.expires_at();
    let context = f
        .broker
        .claim_issue_context(
            recovery_measurements(&f, [9; 32], [17; 32]),
            [21; 32],
            f.continuation,
            7,
            8,
        )
        .unwrap();
    let mut channel = RecordingChannel::default();
    let receipt = f
        .broker
        .issue_ticket(
            accepted,
            f.continuation,
            &context,
            60,
            &f.store,
            &mut channel,
        )
        .unwrap();
    assert_eq!(receipt.expires_at_high_water(), expiry);
    assert_eq!(
        receipt.operation().action(),
        CredentialOperationAction::Revoke
    );
    assert_eq!(channel.frames.len(), 1);
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
        binding,
        ..
    } = CredentialBrokerFrameCodec::decode(&channel.frames[0]).unwrap()
    else {
        panic!()
    };
    let claim = zeroize::Zeroizing::new(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::Claim {
            operation_id,
            attempt,
            ticket,
            binding,
            secret_offer: None,
        })
        .unwrap(),
    );
    channel.queue_received(claim);
    let mut claimed = f
        .broker
        .claim_ticket_from_channel(
            receipt,
            f.continuation,
            7,
            8,
            recovery_measurements(&f, [9; 32], [17; 32]),
            &f.store,
            &mut channel,
        )
        .unwrap();
    assert!(
        f.broker
            .release_control_only_effect(&claimed, operation_id, &f.store, &mut channel)
            .is_err()
    );
    assert!(claimed.take_secret_relay().unwrap().is_none());
    let before = channel.frames.len();
    assert!(
        f.broker
            .release_control_only_effect(
                &claimed,
                CredentialOperationId::from_bytes([99; 16]).unwrap(),
                &f.store,
                &mut channel
            )
            .is_err()
    );
    assert_eq!(channel.frames.len(), before);
    f.broker
        .release_control_only_effect(&claimed, operation_id, &f.store, &mut channel)
        .unwrap();
    assert!(
        matches!(CredentialBrokerFrameCodec::decode(channel.frames.last().unwrap()).unwrap(),
        CredentialBrokerFrame::NativeEffectRelease { operation_id: released, .. } if released == operation_id)
    );
    assert_eq!(
        f.store.load_operation(operation_id).unwrap().state(),
        CredentialOperationState::Claimed
    );
    f.store
        .mark_native_effect_observed(ObserveNativeEffect::new(
            operation_id,
            CredentialNativeEffectDisposition::PossibleEffect,
        ))
        .unwrap();
    let sent = channel.frames.len();
    assert!(
        f.broker
            .release_control_only_effect(&claimed, operation_id, &f.store, &mut channel)
            .is_err()
    );
    assert_eq!(channel.frames.len(), sent);
}

fn recovery_measurements(
    f: &Fixture,
    release: [u8; 32],
    session: [u8; 32],
) -> CredentialMeasurementSnapshot {
    let a = &f.measurements;
    CredentialMeasurementSnapshot::new(
        a.candidate_source_identity([10; 32]).unwrap(),
        a.release_manifest_digest(release).unwrap(),
        a.desktop_executable_identity([12; 32]).unwrap(),
        a.writer_executable_identity([13; 32]).unwrap(),
        a.reader_executable_identity([14; 32]).unwrap(),
        a.contract_bundle_digest([15; 32]).unwrap(),
        a.daemon_authority_id([16; 32]).unwrap(),
        a.protected_session_id(session).unwrap(),
        a.desktop_supervisor_generation(8).unwrap(),
        a.writer_launch_id([18; 32]).unwrap(),
        a.writer_process_start_identity([19; 32]).unwrap(),
        a.writer_process_handle_identity([20; 32]).unwrap(),
        a.broker_channel_binding([21; 32]).unwrap(),
        a.continuation_binding_digest(f.continuation.as_bytes())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn broker_recovery_issue_rejects_channel_substitution_before_persistence() {
    let f = fixture();
    let context = issue_context(&f);
    let mut channel = RecordingChannel::with_channel_binding([99; 32]);
    assert!(
        f.broker
            .issue_ticket(
                f.operation.clone(),
                f.continuation,
                &context,
                60,
                &f.store,
                &mut channel
            )
            .is_err()
    );
    assert!(channel.frames.is_empty());
    let mut valid = RecordingChannel::default();
    let receipt = f
        .broker
        .issue_ticket(
            f.operation,
            f.continuation,
            &context,
            60,
            &f.store,
            &mut valid,
        )
        .unwrap();
    assert_eq!(receipt.ticket_attempt().get(), 1);
}

#[test]
fn broker_recovery_issue_rejects_measurement_substitution_before_attachment() {
    for (release, session, database, supervisor) in [
        ([99; 32], [17; 32], 7, 8),
        ([9; 32], [99; 32], 7, 8),
        ([9; 32], [17; 32], 99, 8),
        ([9; 32], [17; 32], 7, 99),
    ] {
        let (f, accepted) = recovery_fixture();
        let context = f
            .broker
            .claim_issue_context(
                recovery_measurements(&f, release, session),
                [21; 32],
                f.continuation,
                database,
                supervisor,
            )
            .unwrap();
        let mut channel = RecordingChannel::default();
        assert!(
            f.broker
                .issue_ticket(
                    accepted,
                    f.continuation,
                    &context,
                    60,
                    &f.store,
                    &mut channel
                )
                .is_err()
        );
        assert!(channel.frames.is_empty());
        assert!(
            f.store
                .issue_ticket_attempt(
                    IssueCredentialTicketDigest::new(
                        f.operation.operation_id(),
                        digest(71),
                        f.continuation,
                        20
                    )
                    .unwrap()
                )
                .is_err()
        );
    }
}

#[test]
fn broker_recovery_issue_rejects_foreign_witness_and_metadata_only_replay() {
    let (f, accepted) = recovery_fixture();
    let (_, foreign) = recovery_fixture();
    let context = f
        .broker
        .claim_issue_context(
            recovery_measurements(&f, [9; 32], [17; 32]),
            [21; 32],
            f.continuation,
            7,
            8,
        )
        .unwrap();
    let mut channel = RecordingChannel::default();
    assert!(
        f.broker
            .issue_ticket(
                foreign,
                f.continuation,
                &context,
                60,
                &f.store,
                &mut channel
            )
            .is_err()
    );
    assert!(
        f.broker
            .issue_ticket(
                f.operation.clone(),
                f.continuation,
                &context,
                60,
                &f.store,
                &mut channel
            )
            .is_err()
    );
    assert!(channel.frames.is_empty());
    let receipt = f
        .broker
        .issue_ticket(
            accepted,
            f.continuation,
            &context,
            60,
            &f.store,
            &mut channel,
        )
        .unwrap();
    assert_eq!(receipt.ticket_attempt().get(), 1);
    assert!(
        f.broker
            .issue_ticket(
                f.operation,
                f.continuation,
                &context,
                60,
                &f.store,
                &mut channel
            )
            .is_err()
    );
    assert_eq!(channel.frames.len(), 1);
}
