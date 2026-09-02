use super::super::*;
use super::support::{auth, binding, mutated_bindings};

#[test]
fn request_and_ack_frames_reject_bad_length_mac_trailing_and_oversized_bytes() {
    let authenticator = auth(7);
    let mut request = authenticator
        .authenticate_registration(binding())
        .unwrap()
        .into_bytes();
    let mut wrong_length = request.clone();
    wrong_length[13] ^= 1;
    assert!(authenticator.decode_registration(&wrong_length).is_err());
    let short = request[..request.len() - 1].to_vec();
    assert!(authenticator.decode_registration(&short).is_err());
    *request.last_mut().unwrap() ^= 1;
    assert!(authenticator.decode_registration(&request).is_err());
    request.push(0);
    assert!(authenticator.decode_registration(&request).is_err());
    assert!(
        authenticator
            .decode_registration(&vec![0; CREDENTIAL_SERVICE_MAX_FRAME_BYTES + 1])
            .is_err()
    );

    let request = authenticator.authenticate_registration(binding()).unwrap();
    let mut ack = authenticator
        .registration_ack_unchecked(&request)
        .unwrap()
        .into_bytes();
    let mut wrong_length = ack.clone();
    wrong_length[13] ^= 1;
    assert_eq!(
        super::super::codec::decode_ack(&wrong_length),
        Err(CredentialServiceRegistrationError::InvalidFrame)
    );
    let short = ack[..ack.len() - 1].to_vec();
    assert_eq!(
        super::super::codec::decode_ack(&short),
        Err(CredentialServiceRegistrationError::InvalidFrame)
    );
    *ack.last_mut().unwrap() ^= 1;
    assert_eq!(
        authenticator.decode_and_verify_ack_for(&ack, &binding(), 99),
        Err(CredentialServiceRegistrationError::AuthenticationFailed)
    );
    ack.push(0);
    assert_eq!(
        super::super::codec::decode_ack(&ack),
        Err(CredentialServiceRegistrationError::InvalidFrame)
    );
    assert_eq!(
        super::super::codec::decode_ack(&vec![0; CREDENTIAL_SERVICE_MAX_FRAME_BYTES + 1]),
        Err(CredentialServiceRegistrationError::InvalidFrame)
    );
}

#[test]
fn ack_is_deterministic_and_authenticates_the_full_binding() {
    let authenticator = auth(7);
    let request = authenticator
        .authenticate_registration(binding())
        .unwrap()
        .into_bytes();
    let make_ack = || {
        authenticator
            .registration_ack(
                authenticator
                    .decode_and_verify_registration_for(&request, &binding(), 99)
                    .unwrap(),
                99,
            )
            .unwrap()
            .into_bytes()
    };
    let first = make_ack();
    assert_eq!(first, make_ack());
    assert!(
        authenticator
            .decode_and_verify_ack_for(&first, &binding(), 99)
            .is_ok()
    );
    for changed in mutated_bindings() {
        assert!(
            authenticator
                .decode_and_verify_ack_for(&first, &changed, 99)
                .is_err()
        );
    }
    assert_eq!(
        authenticator.decode_and_verify_ack_for(&first, &binding(), 100),
        Err(CredentialServiceRegistrationError::Expired)
    );
}

#[test]
fn golden_wire_vectors_pin_derivation_xpc_role_and_message_domains() {
    let authenticator = auth(7);
    let request = authenticator.authenticate_registration(binding()).unwrap();
    assert_eq!(
        hex::encode(request.into_bytes()),
        "524e4352454430310001000000c00202020202020202020202020202020201010101010170018001010101010101000000000000000b000000000000000c000000000000000d000000000000000e0303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505000000000000000200000000000000640f2cd3f419033e8dd6406cec4e7c168195004617f57c129651ee5012fdffac6a"
    );

    let request = authenticator
        .authenticate_registration(binding())
        .unwrap()
        .into_bytes();
    let ack = authenticator
        .registration_ack(
            authenticator
                .decode_and_verify_registration_for(&request, &binding(), 99)
                .unwrap(),
            99,
        )
        .unwrap();
    assert_eq!(
        hex::encode(ack.into_bytes()),
        "524e43524544303100010000005002020202020202020202020202020202010101010101700180010101010101010000000000000002000000000000000e87bbc574bf3126f5eda9ef12b493f651fe00127f593485cd136d49f2cfad2a42"
    );
}
