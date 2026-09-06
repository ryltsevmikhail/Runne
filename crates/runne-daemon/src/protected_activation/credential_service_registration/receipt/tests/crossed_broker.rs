use super::*;
use runne_api::{
    CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerHandoffContext,
    ProviderCredentialBrokerHandoffFrame,
};

#[tokio::test]
async fn crossed_broker_offer_waits_for_verified_registration_without_replay() {
    for tamper_ack in [false, true] {
        let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
        let parent_expiry = fixture.credential_service_parent_expiry();
        let owned = fixture.owned_launch().unwrap();
        let (desktop, peer) = UnixStream::pair().unwrap();
        desktop
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        let daemon = std::thread::spawn(move || -> Result<[u8; 16], LaunchAuthorityError> {
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
            let service = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
            peer.write_control_frame(
                &service.require_rejoin(binding.clone()).into_control_frame(),
            )?;
            let received = receive(
                &mut peer,
                &keys,
                &ExpectedCredentialServiceRegistration::from_rejoin(&binding, parent_expiry),
                started,
                interleaved::receive,
                now,
            )?;
            let frame = received
                .deferred
                .expect("OFFER waits for verified registration");
            let context = ProviderCredentialBrokerHandoffContext::new(
                *owned.stable().authority_id(),
                *owned.session_id(),
                owned.launch_generation(),
                [31; 32],
            )?;
            let auth = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
            let tick = runne_platform_desktop::MacOsContinuousClock::now_millis()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?;
            let offer = ProviderCredentialBrokerHandoffFrame::decode_and_verify(
                &frame,
                &auth,
                &context,
                ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
                ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
                [0; 16],
                tick,
            )?;
            peer.write_control_frame(&offer.ready(&auth).encode_frame())?;
            assert!(
                peer.read_control_frame().is_err(),
                "OFFER must not be replayed"
            );
            Ok(*offer.nonce())
        });
        let result =
            runne_platform_desktop::test_only_crossed_broker_offer(fixture, desktop, tamper_ack)
                .await;
        let receipt = daemon.join().unwrap();
        if tamper_ack {
            assert!(result.is_err());
            assert!(receipt.is_err());
        } else {
            assert_eq!(result.unwrap(), receipt.unwrap());
        }
    }
}
