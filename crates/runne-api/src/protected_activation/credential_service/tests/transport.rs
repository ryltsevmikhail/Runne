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
    assert_eq!(&bytes[8..10], &1_u16.to_be_bytes());
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
        .authenticate_runtime_reply(*expected.installation_owner(), b"canonical-reply")
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
fn registration_and_runtime_frames_transfer_allocations_without_copying() {
    let desktop = auth(7);
    let install = desktop.registration_install(binding()).unwrap();
    let install_allocation = install.test_bytes().as_ptr();
    assert_eq!(install.into_transport_bytes().as_ptr(), install_allocation);

    let envelope = desktop
        .authenticate_runtime_request([9; 32], b"canonical-provider-frame")
        .unwrap();
    let envelope_allocation = envelope.test_bytes().as_ptr();
    assert_eq!(
        envelope.into_transport_bytes().as_ptr(),
        envelope_allocation
    );
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
    let owner = [9_u8; 32];
    let provider_frame = b"RNCRED01\0\x02single-canonical-provider-request";
    let envelope = auth
        .authenticate_runtime_request(owner, provider_frame)
        .unwrap();
    let bytes = envelope.test_bytes().to_vec();
    assert_eq!(
        CredentialServiceSessionAuthenticator::runtime_routing_owner(&bytes).unwrap(),
        owner
    );
    let verified = auth.verify_runtime_request(owner, &bytes).unwrap();
    let mut decoded = false;
    verified.consume(|payload| {
        decoded = true;
        assert_eq!(payload, provider_frame);
    });
    assert!(decoded);

    let mut tampered = bytes.clone();
    tampered[20] ^= 1;
    assert!(auth.verify_runtime_request(owner, &tampered).is_err());
    assert!(auth.verify_runtime_request([8; 32], &bytes).is_err());
    assert!(auth.verify_runtime_reply(owner, &bytes).is_err());

    let reply = auth
        .authenticate_runtime_reply(owner, provider_frame)
        .unwrap();
    let reply_bytes = reply.test_bytes().to_vec();
    assert!(auth.verify_runtime_reply(owner, &reply_bytes).is_ok());
    assert!(auth.verify_runtime_reply([8; 32], &reply_bytes).is_err());
    assert!(auth.verify_runtime_request(owner, &reply_bytes).is_err());
}

#[test]
fn runtime_envelope_golden_vectors_pin_request_and_reply_v3_domains() {
    let auth = auth(7);
    let owner = [9_u8; 32];
    let provider_frame = b"RNCRED01\0\x02golden-provider-frame";
    let request = auth
        .authenticate_runtime_request(owner, provider_frame)
        .unwrap();
    let reply = auth
        .authenticate_runtime_reply(owner, provider_frame)
        .unwrap();

    assert_eq!(
        hex::encode(request.test_bytes()),
        "524e43524544303100020000005f0909090909090909090909090909090909090909090909090909090909090909524e4352454430310002676f6c64656e2d70726f76696465722d6672616d652134a688244cde73623018a83f53876acea9ba611b478ccaebf7bc2a3c99c6dc"
    );
    assert_eq!(
        hex::encode(reply.test_bytes()),
        "524e43524544303100020000005f0909090909090909090909090909090909090909090909090909090909090909524e4352454430310002676f6c64656e2d70726f76696465722d6672616d6519a9034c7842161ea2c3aaef6eddc36dcb5195fe7cf8f8bb92a094d01eefb297"
    );
}

#[test]
fn runtime_envelope_v2_pins_owner_u16be_u32_length_and_exact_eof() {
    let auth = auth(7);
    let owner = [9_u8; 32];
    let exact_inner = vec![3; 16 * 1024 - 14 - 32 - 32];
    let exact = auth
        .authenticate_runtime_request(owner, &exact_inner)
        .unwrap();
    assert_eq!(exact.test_bytes().len(), 16 * 1024);
    assert_eq!(&exact.test_bytes()[..8], b"RNCRED01");
    assert_eq!(&exact.test_bytes()[8..10], &2_u16.to_be_bytes());
    assert!(
        auth.verify_runtime_request(owner, exact.test_bytes())
            .is_ok()
    );
    assert!(
        auth.authenticate_runtime_request(owner, &vec![3; exact_inner.len() + 1])
            .is_err()
    );

    let mut invalid = exact.test_bytes().to_vec();
    invalid[10..14].reverse();
    assert!(auth.verify_runtime_request(owner, &invalid).is_err());
    let mut trailing = exact.test_bytes().to_vec();
    trailing.push(0);
    assert!(auth.verify_runtime_request(owner, &trailing).is_err());
}

#[test]
fn legacy_ownerless_v1_envelope_cannot_cross_parse_as_owner_routed_v2() {
    let auth = auth(7);
    let owner = [9_u8; 32];
    let frame = b"RNCRED01\0\x01legacy-provider-frame";
    let mac = auth.runtime_mac(
        b"gocode/macos-credential-service/runtime-request/v2\0",
        frame,
    );
    let payload_len = frame.len() + mac.len();
    let mut legacy = Vec::new();
    legacy.extend_from_slice(b"RNCRED01");
    legacy.extend_from_slice(&1_u16.to_be_bytes());
    legacy.extend_from_slice(&u32::try_from(payload_len).unwrap().to_be_bytes());
    legacy.extend_from_slice(frame);
    legacy.extend_from_slice(&mac);
    assert!(auth.verify_runtime_request(owner, &legacy).is_err());
    assert!(CredentialServiceSessionAuthenticator::runtime_routing_owner(&legacy).is_err());
}
