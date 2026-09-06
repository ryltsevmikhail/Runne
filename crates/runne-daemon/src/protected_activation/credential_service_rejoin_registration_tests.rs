use runne_api::{
    CredentialServiceRegistrationBinding, CredentialServiceRejoinBinding,
    CredentialServiceSessionAuthenticator, LaunchSecret,
};

use super::credential_service_registration::{
    ExpectedCredentialServiceRegistration, accept_registration_frames,
};

#[path = "credential_service_rejoin_registration_tests/lifetime.rs"]
mod lifetime;

#[test]
fn rejoin_registration_accepts_fresh_challenge_epoch_but_requires_attempt_and_expiry() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let requested = CredentialServiceRejoinBinding::new(
        [9; 16],
        uuid(1),
        11,
        11,
        13,
        14,
        [3; 32],
        [4; 32],
        2,
        5_100,
    )
    .unwrap();
    let expected = ExpectedCredentialServiceRegistration::from_rejoin(&requested, 480_100);
    let exact = CredentialServiceRegistrationBinding::new(
        [9; 16],
        uuid(1),
        11,
        11,
        13,
        14,
        [3; 32],
        [4; 32],
        [6; 16],
        2,
        480_100,
    )
    .unwrap();
    let (claim, acknowledgement) = registration_frames(&keys, &exact);
    for now in [99, 5_099, 5_100, 480_099] {
        assert_eq!(
            accept_registration_frames(&keys, &expected, &claim, &acknowledgement, now).is_ok(),
            now < 5_100
        );
    }

    let fresh_epoch = CredentialServiceRegistrationBinding::new(
        [8; 16],
        uuid(1),
        11,
        11,
        13,
        14,
        [3; 32],
        [4; 32],
        [7; 16],
        2,
        480_100,
    )
    .unwrap();
    let (claim, acknowledgement) = registration_frames(&keys, &fresh_epoch);
    assert!(accept_registration_frames(&keys, &expected, &claim, &acknowledgement, 99).is_ok());

    for (join_attempt, expiry) in [(3, 480_100), (2, 480_101), (2, 5_100)] {
        let wrong = CredentialServiceRegistrationBinding::new(
            [8; 16],
            uuid(1),
            11,
            11,
            13,
            14,
            [3; 32],
            [4; 32],
            [7; 16],
            join_attempt,
            expiry,
        )
        .unwrap();
        let (claim, acknowledgement) = registration_frames(&keys, &wrong);
        assert!(
            accept_registration_frames(&keys, &expected, &claim, &acknowledgement, 99).is_err()
        );
    }
}

fn registration_frames(
    keys: &runne_api::ProtectedActivationKeys,
    binding: &CredentialServiceRegistrationBinding,
) -> (Vec<u8>, Vec<u8>) {
    let authenticator = CredentialServiceSessionAuthenticator::from_protected_activation(keys);
    let claim = authenticator
        .authenticate_registration(binding.clone())
        .unwrap()
        .into_bytes();
    let verified = authenticator
        .decode_and_verify_registration_for(&claim, binding, 99)
        .unwrap();
    let acknowledgement = authenticator
        .registration_ack(verified, 99)
        .unwrap()
        .into_bytes();
    (claim, acknowledgement)
}

const fn uuid(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}
