use super::super::*;
use super::support::{auth, binding, mutated_bindings};

#[test]
fn equal_activation_keys_are_deterministic_and_isolated() {
    let first = auth(7);
    let same = auth(7);
    let other = auth(8);
    let request = first.authenticate_registration(binding()).unwrap();
    assert!(
        same.verify_registration_at(&request, &binding(), 99)
            .is_ok()
    );
    assert!(
        other
            .verify_registration_at(&request, &binding(), 99)
            .is_err()
    );
    assert_eq!(
        request.into_bytes(),
        same.authenticate_registration(binding())
            .unwrap()
            .into_bytes()
    );
}

#[test]
fn every_immutable_registration_field_is_authenticated_and_current() {
    let authenticator = auth(7);
    let request = authenticator.authenticate_registration(binding()).unwrap();
    for changed in mutated_bindings() {
        assert!(
            authenticator
                .verify_registration_at(&request, &changed, 99)
                .is_err()
        );
    }
    assert!(
        authenticator
            .verify_registration_at(&request, &binding(), 100)
            .is_err()
    );
}

#[test]
fn current_binding_and_expiry_are_rechecked_before_acknowledgement() {
    let authenticator = auth(7);
    let bytes = authenticator
        .authenticate_registration(binding())
        .unwrap()
        .into_bytes();
    let verified = authenticator
        .decode_and_verify_registration_for(&bytes, &binding(), 99)
        .unwrap();
    assert_eq!(
        authenticator.registration_ack(verified, 100),
        Err(CredentialServiceRegistrationError::Expired)
    );
}

#[test]
fn typed_metadata_accessors_do_not_expose_registration_secret() {
    let authenticator = auth(7);
    let request = authenticator.authenticate_registration(binding()).unwrap();
    assert_eq!(request.binding().service_epoch(), binding().service_epoch());
    let ack = authenticator.registration_ack_unchecked(&request).unwrap();
    assert_eq!(ack.service_epoch(), binding().service_epoch());
    assert_eq!(ack.installed_generation(), 14);
}

#[test]
fn daemon_can_verify_a_registration_claim_before_checking_its_exact_facts() {
    let authenticator = auth(7);
    let expected = binding();
    let frame = authenticator
        .authenticate_registration(expected.clone())
        .unwrap()
        .into_bytes();

    let verified = authenticator
        .decode_and_verify_registration(&frame)
        .unwrap();
    assert!(verified.binding() == &expected);
}
