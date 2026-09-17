use crate::application::provider_credential_enrollment::test_control;
use crate::protected_activation::{
    ProtectedActivationChannel,
    enrollment_v3_tests::{owned_and_sessions, read_frame},
};
use runne_api::ProtectedCredentialEnrollmentShutdownAckV3;

#[test]
fn shutdown_ack_is_observable_only_after_actual_session_revoke() {
    let (control, keys) = test_control();
    let (session, session_id) = control.start_test_published_session(&keys).unwrap();
    assert!(!control.test_status_is_unavailable(session_id));
    let (owned, _, _) = owned_and_sessions();
    let mut acknowledgement = ProtectedCredentialEnrollmentShutdownAckV3::new(owned, true);
    acknowledgement.sign(&keys);
    let (server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
    let observed_control = std::sync::Arc::clone(&control);
    let observer = std::thread::spawn(move || {
        let _ = read_frame(&mut client);
        observed_control.test_status_is_unavailable(session_id)
    });

    let mut runtime = super::runtime::V3EnrollmentRuntime {
        deferred_control: None,
        #[cfg(target_arch = "aarch64")]
        round: None,
        live: None,
        broker: None,
        session: Some(session),
        terminal: true,
        claim_measurements: None,
        channel: None,
        credential_service: None,
        credential_service_configuration: None,
    };
    let mut channel = ProtectedActivationChannel::new(server).unwrap();
    super::write_shutdown_ack_after_revocation(&mut runtime, &mut channel, &acknowledgement)
        .unwrap();

    assert!(observer.join().unwrap());
    assert!(runtime.session.is_none());
}
