use super::*;
use runne_api::{
    ProtectedCredentialEnrollmentShutdownAckV3, ProtectedCredentialEnrollmentShutdownV3,
};

#[tokio::test]
async fn crossed_shutdown_waits_for_registration_and_never_replays_request() {
    for tamper_ack in [false, true] {
        let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
        let owned = fixture.owned_launch().unwrap();
        let (desktop, peer) = UnixStream::pair().unwrap();
        desktop
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        let daemon = std::thread::spawn(move || -> Result<(), LaunchAuthorityError> {
            let keys = runne_api::LaunchSecret::from_bytes([3; 32])
                .unwrap()
                .derive_keys();
            let started = now()?;
            let enrollment = owned.enrollment_binding();
            let binding = CredentialServiceRejoinBinding::new(
                [9; 16],
                *owned.session_id(),
                owned.launch_generation(),
                owned.launch_generation(),
                enrollment.desktop_supervisor_generation(),
                1,
                *enrollment.installation_identity_digest(),
                *enrollment.release_tuple_digest(),
                2,
                started + 5_000,
            )
            .unwrap();
            let frame = CredentialServiceSessionAuthenticator::from_protected_activation(&keys)
                .require_rejoin(binding.clone())
                .into_control_frame();
            peer.write_control_frame(&frame)?;
            let received = receive(
                &mut peer,
                &keys,
                &ExpectedCredentialServiceRegistration::from_rejoin(&binding),
                started,
                interleaved::receive,
                now,
            )?;
            assert_eq!(received.session.binding().join_attempt(), 2);
            let frame = received
                .deferred
                .expect("original shutdown retained until verified ACK");
            let shutdown = ProtectedCredentialEnrollmentShutdownV3::decode_frame(&frame).unwrap();
            shutdown.verify_exact(&owned, &keys)?;
            let mut ack = ProtectedCredentialEnrollmentShutdownAckV3::new(owned, true);
            ack.sign(&keys);
            peer.write_control_frame(&ack.encode_frame().unwrap())?;
            // No second shutdown request follows the authenticated acknowledgement.
            assert!(peer.read_control_frame().is_err());
            Ok(())
        });
        let result =
            runne_platform_desktop::test_only_crossed_shutdown(fixture, desktop, tamper_ack).await;
        let receipt = daemon.join().unwrap();
        if tamper_ack {
            assert!(result.is_err());
            assert!(
                receipt.is_err(),
                "invalid ACK cannot release deferred shutdown"
            );
        } else {
            assert!(result.unwrap());
            receipt.unwrap();
        }
    }
}
