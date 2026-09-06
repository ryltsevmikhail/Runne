use super::*;

#[test]
fn rejoin_preparation_retains_exact_authenticated_expiry_and_caps_exchange() {
    let fixture = runne_platform_desktop::test_only_ready_v3_enrollment_supervisor();
    let owned = fixture.owned_launch().unwrap();
    fixture.into_supervisor().stop().unwrap();
    let keys = runne_api::LaunchSecret::from_bytes([7; 32])
        .unwrap()
        .derive_keys();
    let enrollment = owned.enrollment_binding();
    let binding = CredentialServiceRegistrationBinding::new(
        [9; 16],
        *owned.session_id(),
        owned.launch_generation(),
        owned.launch_generation(),
        enrollment.desktop_supervisor_generation(),
        1,
        *enrollment.installation_identity_digest(),
        *enrollment.release_tuple_digest(),
        [6; 16],
        1,
        480_100,
    )
    .unwrap();
    let auth = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
    let claim = auth
        .authenticate_registration(binding.clone())
        .unwrap()
        .into_bytes();
    let verified = auth
        .decode_and_verify_registration_for(&claim, &binding, 99)
        .unwrap();
    let ack = auth.registration_ack(verified, 99).unwrap().into_bytes();
    let session = accept_registration_frames(
        &keys,
        &ExpectedCredentialServiceRegistration::from_binding(&binding),
        &claim,
        &ack,
        99,
    )
    .unwrap();
    for requested in [5_100, 490_100] {
        let prepared = session
            .prepare_rejoin_binding(
                CredentialServiceEpoch::from_bytes([8; 16]).unwrap(),
                &owned,
                requested,
            )
            .unwrap();
        let expected_deadline = requested.min(480_100);
        assert_eq!(prepared.binding.expires_at_unix_millis(), expected_deadline);
        assert_eq!(prepared.expected.receipt_deadline, Some(expected_deadline));
        assert_eq!(prepared.expected.exact_expiry, Some(480_100));
        assert_eq!(prepared.binding.join_attempt(), 2);
    }
}
