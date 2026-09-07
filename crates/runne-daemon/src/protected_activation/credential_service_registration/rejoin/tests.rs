use super::*;
use crate::protected_activation::enrollment_v3_tests::owned_and_sessions;
use runne_api::{
    ProtectedCredentialEnrollmentRenewRequestV3, ProtectedCredentialEnrollmentRenewTicketV3,
};

fn registered_session(
    keys: &runne_api::ProtectedActivationKeys,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> CredentialServiceRuntimeSession {
    registered_session_with_generation(keys, owned, owned.launch_generation())
}

fn registered_session_with_generation(
    keys: &runne_api::ProtectedActivationKeys,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    generation: u64,
) -> CredentialServiceRuntimeSession {
    registered_session_with_generations(keys, owned, generation, generation)
}

fn registered_session_with_generations(
    keys: &runne_api::ProtectedActivationKeys,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    runtime_generation: u64,
    daemon_authority_generation: u64,
) -> CredentialServiceRuntimeSession {
    let enrollment = owned.enrollment_binding();
    let binding = CredentialServiceRegistrationBinding::new(
        [9; 16],
        *owned.session_id(),
        daemon_authority_generation,
        runtime_generation,
        enrollment.desktop_supervisor_generation(),
        1,
        *enrollment.installation_identity_digest(),
        *enrollment.release_tuple_digest(),
        [6; 16],
        1,
        480_100,
    )
    .unwrap();
    let auth = CredentialServiceSessionAuthenticator::from_protected_activation(keys);
    let claim = auth
        .authenticate_registration(binding.clone())
        .unwrap()
        .into_bytes();
    let verified = auth
        .decode_and_verify_registration_for(&claim, &binding, 99)
        .unwrap();
    let ack = auth.registration_ack(verified, 99).unwrap().into_bytes();
    accept_registration_frames(
        keys,
        &ExpectedCredentialServiceRegistration::from_binding(&binding),
        &claim,
        &ack,
        99,
    )
    .unwrap()
}

fn rotated_owned_launch(
    owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    keys: &runne_api::ProtectedActivationKeys,
) -> runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3 {
    let mut renewal = ProtectedCredentialEnrollmentRenewRequestV3::new(owned, 1, [17; 32]).unwrap();
    renewal.sign(keys);
    let next_session = *uuid::Uuid::now_v7().as_bytes();
    let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
        &renewal,
        next_session,
        [19; 32],
        1_000,
        2_000,
    )
    .unwrap();
    ticket.sign(keys);
    ticket
        .verify_exact_at(&renewal, 1_000, keys)
        .unwrap()
        .next_owned_launch()
}

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

#[test]
fn rejoin_preparation_allows_only_authenticated_current_session_supersession() {
    let (owned, keys, _) = owned_and_sessions();
    let session = registered_session(&keys, &owned);
    let rotated = rotated_owned_launch(owned.clone(), &keys);

    assert_ne!(rotated.session_id(), owned.session_id());
    assert_eq!(rotated.launch_generation(), owned.launch_generation());
    assert_eq!(rotated.enrollment_binding(), owned.enrollment_binding());

    let prepared = session
        .prepare_rejoin_binding(
            CredentialServiceEpoch::from_bytes([8; 16]).unwrap(),
            &rotated,
            5_100,
        )
        .unwrap();
    assert_eq!(
        prepared.binding.protected_session_id(),
        *rotated.session_id()
    );
    assert_eq!(
        prepared.binding.runtime_generation(),
        owned.launch_generation()
    );
    assert_eq!(
        prepared.binding.daemon_authority_generation(),
        owned.launch_generation()
    );
    assert_eq!(
        prepared.binding.supervisor_generation(),
        owned.enrollment_binding().desktop_supervisor_generation()
    );
    assert_eq!(prepared.binding.join_attempt(), 2);

    let stale_generation = registered_session_with_generation(
        &keys,
        &owned,
        owned.launch_generation().checked_add(1).unwrap(),
    );
    assert!(matches!(
        stale_generation.prepare_rejoin_binding(
            CredentialServiceEpoch::from_bytes([8; 16]).unwrap(),
            &rotated,
            5_100,
        ),
        Err(LaunchAuthorityError::OwnershipMismatch)
    ));

    let stale_daemon_generation = registered_session_with_generations(
        &keys,
        &owned,
        owned.launch_generation(),
        owned.launch_generation().checked_add(1).unwrap(),
    );
    assert!(matches!(
        stale_daemon_generation.prepare_rejoin_binding(
            CredentialServiceEpoch::from_bytes([8; 16]).unwrap(),
            &rotated,
            5_100,
        ),
        Err(LaunchAuthorityError::OwnershipMismatch)
    ));
}
