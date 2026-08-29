use std::os::unix::net::UnixStream;
use std::sync::{Arc, atomic::Ordering};

use runne_api::ProtectedCredentialEnrollmentPrepareV2;

use super::enrollment_control_exchange::run_enrollment_control_exchange_with;
use super::enrollment_control_transition_fixture::{
    CountedGenerationStore, composition, prepare_and_owned, protected_service, v2_launch,
    v2_launch_with_secret,
};

#[test]
fn stale_reservation_fails_closed_and_preserves_the_current_session() {
    let (original, owned, keys, _provider) = v2_launch();
    let prepare = prepare_and_owned(&owned, &keys);
    let store = CountedGenerationStore::starting_at(5);
    let (sessions, current) = protected_service(&store);
    let (_client, daemon) = UnixStream::pair().unwrap();
    let mut channel = super::ProtectedActivationChannel::new(daemon).unwrap();
    let clock: Arc<dyn Fn() -> std::time::Duration + Send + Sync> =
        Arc::new(|| std::time::Duration::ZERO);

    // A competing reserve consumes the exact successor; the pending
    // expectation can no longer be satisfied and must fail closed.
    use runne_application::local_session::EnrollmentLaunchGenerationStore;
    store
        .reserve_next_enrollment_generation()
        .expect("competing reservation");
    let outcome = run_enrollment_control_exchange_with(
        &mut channel,
        &prepare,
        &keys,
        &owned,
        &composition(&original),
        &sessions,
        &clock,
        |_, _, _| true,
        |input, request, channel| {
            super::enrollment_transition_v2_v3::transition_with(
                input,
                request,
                |_, _| true,
                channel,
            )
        },
    );
    assert!(outcome.is_err());
    assert_eq!(
        sessions
            .lock()
            .unwrap()
            .current_binding()
            .ephemeral()
            .launch_generation(),
        4
    );
    assert_eq!(sessions.lock().unwrap().current_binding(), &current);
}

#[test]
fn foreign_mac_prepare_is_rejected_before_any_reservation_or_wire_traffic() {
    let (original, owned, keys, _provider) = v2_launch();
    let foreign = {
        let (_foreign_original, _foreign_owned, foreign_keys, _) =
            v2_launch_with_secret([0x66; 32]);
        let mut prepare = ProtectedCredentialEnrollmentPrepareV2::new(
            owned.clone(),
            1,
            [21; 32],
            [7; 32],
            [8; 32],
            [9; 32],
            1,
        )
        .unwrap();
        prepare.sign(&foreign_keys);
        (prepare, foreign_keys)
    };
    let store = CountedGenerationStore::starting_at(5);
    let (sessions, current) = protected_service(&store);
    let (_client, daemon) = UnixStream::pair().unwrap();
    let mut channel = super::ProtectedActivationChannel::new(daemon).unwrap();
    let clock: Arc<dyn Fn() -> std::time::Duration + Send + Sync> =
        Arc::new(|| std::time::Duration::ZERO);

    let outcome = run_enrollment_control_exchange_with(
        &mut channel,
        &foreign.0,
        &keys,
        &owned,
        &composition(&original),
        &sessions,
        &clock,
        |_, _, _| true,
        |input, request, channel| {
            super::enrollment_transition_v2_v3::transition_with(
                input,
                request,
                |_, _| true,
                channel,
            )
        },
    );
    assert!(outcome.is_err());
    assert!(store.reserved.load(Ordering::Relaxed) == 0);
    assert_eq!(sessions.lock().unwrap().current_binding(), &current);
}
