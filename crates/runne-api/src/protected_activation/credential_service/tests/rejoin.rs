use crate::{
    CredentialServiceRegistrationError, CredentialServiceRejoinBinding,
    CredentialServiceSessionAuthenticator, LaunchSecret,
};

#[test]
fn rejoin_request_is_authenticated_strict_and_expiring() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let authenticator = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
    let frame = authenticator.require_rejoin(binding()).into_control_frame();

    let verified = authenticator.decode_and_verify_rejoin(&frame, 99).unwrap();
    assert_eq!(verified.binding(), &binding());
    assert!(matches!(
        authenticator.decode_and_verify_rejoin(&frame, 200),
        Err(CredentialServiceRegistrationError::Expired)
    ));
}

#[test]
fn rejoin_request_rejects_tampering_wrong_key_and_noncanonical_frames() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let authenticator = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
    let frame = authenticator.require_rejoin(binding()).into_control_frame();
    let other = CredentialServiceSessionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys(),
    );
    assert!(matches!(
        other.decode_and_verify_rejoin(&frame, 99),
        Err(CredentialServiceRegistrationError::AuthenticationFailed)
    ));
    for index in [0, 4, 12, 14, frame.len() - 1] {
        let mut tampered = frame.clone();
        tampered[index] ^= 1;
        assert!(
            authenticator
                .decode_and_verify_rejoin(&tampered, 99)
                .is_err()
        );
    }
    let mut trailing = frame;
    trailing.push(0);
    assert!(
        authenticator
            .decode_and_verify_rejoin(&trailing, 99)
            .is_err()
    );
}

fn binding() -> CredentialServiceRejoinBinding {
    CredentialServiceRejoinBinding::new(
        [1; 16],
        [2, 2, 2, 2, 2, 2, 0x70, 2, 0x80, 2, 2, 2, 2, 2, 2, 2],
        3,
        3,
        4,
        5,
        [6; 32],
        [7; 32],
        2,
        200,
    )
    .unwrap()
}
