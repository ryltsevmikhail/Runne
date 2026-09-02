use super::support::{auth, binding};
use crate::protected_activation::credential_service::{
    CredentialServiceRegistrationError, CredentialServiceSessionAuthenticator,
};

#[test]
fn install_verifies_mac_before_policy_and_returns_key_only_after_acceptance() {
    let desktop = auth(7);
    let expected = binding();
    let install = desktop.registration_install(expected.clone()).unwrap();
    let bytes = install.test_bytes().to_vec();
    let mut policy_saw_authenticated_binding = false;
    let accepted = CredentialServiceSessionAuthenticator::accept_registration_install_with_policy(
        &bytes,
        50,
        |claimed| {
            policy_saw_authenticated_binding = true;
            assert!(claimed == &expected);
            Ok(())
        },
    )
    .unwrap();
    assert!(policy_saw_authenticated_binding);
    let (service, ack) = accepted.complete(50).unwrap();
    desktop
        .decode_and_verify_ack_for(&ack.into_bytes(), &expected, 50)
        .unwrap();
    let envelope = service
        .authenticate_runtime_reply(b"canonical-reply")
        .unwrap();
    assert!(!envelope.test_bytes().is_empty());

    assert!(matches!(
        CredentialServiceSessionAuthenticator::accept_registration_install_with_policy(
            &bytes,
            50,
            |_| Err(CredentialServiceRegistrationError::BindingMismatch),
        ),
        Err(CredentialServiceRegistrationError::BindingMismatch)
    ));
}

#[test]
fn install_rejects_tamper_and_strict_frame_before_policy() {
    let desktop = auth(7);
    let install = desktop.registration_install(binding()).unwrap();
    let baseline = install.test_bytes().to_vec();
    for index in [0_usize, 9, 13, baseline.len() - 1] {
        let mut invalid = baseline.clone();
        invalid[index] ^= 1;
        let mut called = false;
        assert!(
            CredentialServiceSessionAuthenticator::accept_registration_install_with_policy(
                &invalid,
                50,
                |_| {
                    called = true;
                    Ok(())
                },
            )
            .is_err()
        );
        assert!(!called);
    }
    let mut trailing = baseline;
    trailing.push(0);
    assert!(
        CredentialServiceSessionAuthenticator::accept_registration_install_with_policy(
            &trailing,
            50,
            |_| Ok(()),
        )
        .is_err()
    );
}

#[test]
fn runtime_mac_authenticates_one_exact_provider_frame_before_decode() {
    let auth = auth(7);
    let provider_frame = b"RNCRED01\0\x01single-canonical-provider-request";
    let envelope = auth.authenticate_runtime_request(provider_frame).unwrap();
    let bytes = envelope.test_bytes().to_vec();
    let verified = auth.verify_runtime_request(&bytes).unwrap();
    let mut decoded = false;
    verified.consume(|payload| {
        decoded = true;
        assert_eq!(payload, provider_frame);
    });
    assert!(decoded);

    let mut tampered = bytes.clone();
    tampered[20] ^= 1;
    assert!(auth.verify_runtime_request(&tampered).is_err());
    assert!(auth.verify_runtime_reply(&bytes).is_err());

    let reply = auth.authenticate_runtime_reply(provider_frame).unwrap();
    let reply_bytes = reply.test_bytes().to_vec();
    assert!(auth.verify_runtime_reply(&reply_bytes).is_ok());
    assert!(auth.verify_runtime_request(&reply_bytes).is_err());
}

#[test]
fn runtime_envelope_pins_rncred01_u16be_u32_length_and_exact_eof() {
    let auth = auth(7);
    let exact_inner = vec![3; 16 * 1024 - 14 - 32];
    let exact = auth.authenticate_runtime_request(&exact_inner).unwrap();
    assert_eq!(exact.test_bytes().len(), 16 * 1024);
    assert_eq!(&exact.test_bytes()[..8], b"RNCRED01");
    assert_eq!(&exact.test_bytes()[8..10], &1_u16.to_be_bytes());
    assert!(auth.verify_runtime_request(exact.test_bytes()).is_ok());
    assert!(
        auth.authenticate_runtime_request(&vec![3; exact_inner.len() + 1])
            .is_err()
    );

    let mut invalid = exact.test_bytes().to_vec();
    invalid[10..14].reverse();
    assert!(auth.verify_runtime_request(&invalid).is_err());
    let mut trailing = exact.test_bytes().to_vec();
    trailing.push(0);
    assert!(auth.verify_runtime_request(&trailing).is_err());
}
