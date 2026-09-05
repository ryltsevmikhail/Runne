use super::*;
use crate::application::provider_credential_enrollment::tests::broker_recovery_issue::fixture::prepared_cleanup_fixture;
use runne_api::{
    LaunchSecret, ProtectedCredentialRecoveryBootstrap, ProtectedCredentialRecoveryCodec,
};
use runne_provider::ProviderCredentialEnrollmentStore;

mod discovery;
mod supersession;

fn with_session(
    case: u8,
    test: impl FnOnce(
        DaemonProtectedCredentialEnrollmentSession,
        ProtectedCredentialRecoveryCodec,
        Arc<DaemonProviderCredentialEnrollmentControl>,
        CredentialOperationId,
        u64,
    ),
) {
    let f = prepared_cleanup_fixture();
    let operation = f.operation.operation_id();
    let control = Arc::new(
        DaemonProviderCredentialEnrollmentControl::new(
            Arc::new(f.store),
            Arc::new(super::super::super::protected_session_tests::NoReadback),
            (*f.measurements).clone(),
            f.enrollment_authority,
            [9; 16],
            7,
            #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
            None,
        )
        .unwrap(),
    );
    let mut facts = ProtectedEnrollmentSessionFacts::for_test();
    facts.installation = [3; 32];
    facts.release = [9; 32];
    facts.database_generation = 7;
    if case == 1 {
        facts.installation = [99; 32];
    }
    if case == 2 {
        facts.release = [99; 32];
    }
    let rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let broker = runne_api::protected_credential_broker_evidence_binding(
        facts.release,
        rendezvous.channel_binding(),
        rendezvous.publication_public_key(),
    );
    let known = ProtectedCredentialRecoveryBootstrap::new(
        facts.installation,
        facts.release,
        session_binding(&facts),
        facts.tauri_peer,
        broker,
        facts.supervisor_generation,
    )
    .unwrap();
    let keys = LaunchSecret::from_bytes([71; 32]).unwrap().derive_keys();
    let desktop = ProtectedCredentialRecoveryCodec::for_desktop(&keys, known).unwrap();
    let session = control
        .start_test_protected_session(&keys, facts, rendezvous)
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    test(session, desktop, control, operation, now);
}

#[test]
fn session_recovery_terminal_uses_accepted_offer_binding() {
    with_session(0, |mut session, mut desktop, _, operation, now| {
        let request = desktop
            .encode_desktop_request(operation.as_bytes())
            .unwrap();
        let frame = session.offer_cleanup_recovery(&request, now).unwrap();
        let offer = desktop.decode_daemon_offer(&frame, now).unwrap();
        let ack = desktop.encode_desktop_accept(&offer, now).unwrap();
        session.accept_cleanup_recovery(&ack, now).unwrap();
        // Transport projection only: this test does not execute a native effect.
        let snapshot = runne_api::ProviderCredentialOperationSnapshotV2::new(
            runne_api::ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
            None,
            runne_api::ProviderCredentialProviderV2::OpenAi,
            runne_api::ProviderCredentialOperationKindV2::Revoke,
            runne_api::ProviderCredentialOperationStateV2::Completed,
            3,
            3,
            false,
            None,
        )
        .unwrap();
        let frame = session.encode_terminal_snapshot(snapshot.clone()).unwrap();
        assert_eq!(desktop.decode_daemon_terminal(&frame).unwrap(), snapshot);
    });
}

#[test]
fn session_recovery_retains_durable_witness_and_one_endpoint_without_begin() {
    with_session(0, |mut session, mut desktop, control, operation, now| {
        assert!(session.require_durable_terminal().is_err());
        let request = desktop
            .encode_desktop_request(operation.as_bytes())
            .unwrap();
        let (kind, frame) = session
            .accept_initial_request(&request, now * 1000)
            .unwrap();
        assert_eq!(kind, super::super::InitialCredentialExchange::Recovery);
        assert!(session.begun.is_none());
        assert!(session.take_bound_broker_handoff().is_err());
        assert!(session.offer_cleanup_recovery(&request, now).is_err());
        let offer = desktop.decode_daemon_offer(&frame, now).unwrap();
        let ack = desktop.encode_desktop_accept(&offer, now).unwrap();
        session.accept_cleanup_recovery(&ack, now).unwrap();
        assert!(session.require_durable_terminal().is_err());
        assert_eq!(
            session.take_bound_broker_handoff().unwrap().operation_id(),
            operation
        );
        assert!(session.take_bound_broker_handoff().is_err());
        assert!(session.accept_cleanup_recovery(&ack, now).is_err());
        assert!(session.begun.is_none());
        assert_eq!(
            control.store.load_operation(operation).unwrap().state(),
            runne_provider::CredentialOperationState::Prepared
        );
    });
}

#[test]
fn session_recovery_rejects_authenticated_wrong_owner_or_release() {
    for case in [1, 2] {
        with_session(case, |mut session, mut desktop, control, operation, now| {
            let request = desktop
                .encode_desktop_request(operation.as_bytes())
                .unwrap();
            assert!(session.offer_cleanup_recovery(&request, now).is_err());
            assert!(session.take_bound_broker_handoff().is_err());
            assert!(session.recovery.pending.is_none());
            assert!(session.recovery.ready.is_none());
            assert_eq!(
                control.store.load_operation(operation).unwrap().state(),
                runne_provider::CredentialOperationState::Prepared
            );
        });
    }
}

#[test]
fn session_recovery_bad_ack_and_expiry_never_publish_endpoint() {
    for expire in [false, true] {
        with_session(0, |mut session, mut desktop, _, operation, now| {
            let request = desktop
                .encode_desktop_request(operation.as_bytes())
                .unwrap();
            let frame = session.offer_cleanup_recovery(&request, now).unwrap();
            let offer = desktop.decode_daemon_offer(&frame, now).unwrap();
            let valid = desktop.encode_desktop_accept(&offer, now).unwrap();
            let mut ack = valid.clone();
            if !expire {
                *ack.last_mut().unwrap() ^= 1;
            }
            assert!(
                session
                    .accept_cleanup_recovery(
                        &ack,
                        if expire {
                            now + super::CLEANUP_RECOVERY_TTL_SECONDS + 1
                        } else {
                            now
                        },
                    )
                    .is_err()
            );
            assert!(session.take_bound_broker_handoff().is_err());
            assert!(session.accept_cleanup_recovery(&valid, now).is_err());
            assert!(session.recovery.ready.is_none());
        });
    }
}

#[test]
fn cleanup_recovery_lease_remains_short_lived_but_covers_native_handoff() {
    assert_eq!(super::CLEANUP_RECOVERY_TTL_SECONDS, 120);
}

#[test]
fn session_recovery_claim_consumes_witness_without_snapshot_fallback() {
    with_session(0, |mut session, mut desktop, control, operation, now| {
        let request = desktop
            .encode_desktop_request(operation.as_bytes())
            .unwrap();
        let frame = session.offer_cleanup_recovery(&request, now).unwrap();
        assert!(session.take_ticket_authority().is_err());
        assert!(session.recovery_continuation().is_err());
        let offer = desktop.decode_daemon_offer(&frame, now).unwrap();
        let ack = desktop.encode_desktop_accept(&offer, now).unwrap();
        session.accept_cleanup_recovery(&ack, now).unwrap();
        let continuation = session.recovery_continuation().unwrap().unwrap();
        let authority = session.take_ticket_authority().unwrap();
        let crate::application::provider_credential_enrollment::broker::issue::CredentialTicketAuthority::Recovery(witness) = authority else {
            panic!("recovery must not become an intent snapshot");
        };
        assert_eq!(witness.operation().operation_id(), operation);
        assert_eq!(witness.request().continuation_digest(), continuation);
        control.store.attach_cleanup_recovery(*witness).unwrap();
        assert_eq!(session.operation_id().unwrap(), operation);
        assert!(session.take_ticket_authority().is_err());
        assert!(session.recovery_continuation().is_err());
    });
}

#[test]
fn session_recovery_routing_rejects_tampered_frames_without_native_admission() {
    with_session(0, |mut session, mut desktop, _, operation, now| {
        let valid = desktop
            .encode_desktop_request(operation.as_bytes())
            .unwrap();
        let mut bad = valid.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(session.accept_initial_request(&bad, now * 1000).is_err());
        assert!(session.pending.is_none());
        assert!(session.recovery.pending.is_none());
        assert!(session.take_bound_broker_handoff().is_err());
        let (kind, _) = session.accept_initial_request(&valid, now * 1000).unwrap();
        assert_eq!(kind, super::super::InitialCredentialExchange::Recovery);
    });
}
