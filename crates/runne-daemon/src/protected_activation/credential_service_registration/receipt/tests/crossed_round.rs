use super::*;
use runne_api::{ProtectedCredentialRoundBrokerFacts, ProtectedCredentialRoundCodec};

#[tokio::test]
async fn crossed_round_installs_new_broker_only_after_verified_registration() {
    for tamper_ack in [false, true] {
        let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
        let parent_expiry = fixture.credential_service_parent_expiry();
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
                &ExpectedCredentialServiceRegistration::from_rejoin(&binding, parent_expiry),
                started,
                interleaved::receive,
                now,
            )?;
            assert_eq!(received.session.binding().join_attempt(), 2);
            let frame = received
                .deferred
                .expect("original round retained until verified ACK");
            let mut codec = ProtectedCredentialRoundCodec::new(&keys, &owned);
            codec.decode_request(&frame)?;
            let offer = codec.encode_offer(ProtectedCredentialRoundBrokerFacts::new(
                [41; 32], [42; 32],
            )?)?;
            peer.write_control_frame(&offer)?;
            codec.decode_accept(&peer.read_control_frame()?)?;
            // The desktop closes after sending the accept, without replaying round.
            assert!(peer.read_control_frame().is_err());
            Ok(())
        });
        let result =
            runne_platform_desktop::test_only_crossed_round(fixture, desktop, tamper_ack).await;
        let receipt = daemon.join().unwrap();
        if tamper_ack {
            assert!(result.is_err());
            assert!(
                receipt.is_err(),
                "invalid ACK cannot release deferred round"
            );
        } else {
            assert_eq!(result.unwrap(), ([41; 32], [42; 32]));
            receipt.unwrap();
        }
    }
}
