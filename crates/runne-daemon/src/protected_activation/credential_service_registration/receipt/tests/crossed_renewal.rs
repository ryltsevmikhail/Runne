use super::*;
use runne_api::{
    ProtectedCredentialEnrollmentRenewRequestV3 as Request,
    ProtectedCredentialEnrollmentRenewTicketV3 as Ticket,
};

#[tokio::test]
async fn crossed_renewal_queues_one_new_session_only_after_verified_registration() {
    for tamper_ack in [false, true] {
        let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
        let owned = fixture.owned_launch().unwrap();
        let next = *uuid::Uuid::now_v7().as_bytes();
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
                .expect("original renewal retained until verified ACK");
            let request = Request::decode_frame(&frame).unwrap();
            request.verify_exact(&owned, 0, &keys)?;
            let mut ticket = Ticket::new(&request, next, [24; 32], 100, 200)?;
            ticket.sign(&keys);
            peer.write_control_frame(&ticket.encode_frame().unwrap())?;
            // The desktop closes after consuming the ticket, without replaying renewal.
            assert!(peer.read_control_frame().is_err());
            Ok(())
        });
        let result =
            runne_platform_desktop::test_only_crossed_renewal(fixture, desktop, tamper_ack).await;
        let receipt = daemon.join().unwrap();
        if tamper_ack {
            assert!(result.is_err());
            assert!(
                receipt.is_err(),
                "invalid ACK cannot release deferred renewal"
            );
        } else {
            assert_eq!(result.unwrap(), (next, 1));
            receipt.unwrap();
        }
    }
}
