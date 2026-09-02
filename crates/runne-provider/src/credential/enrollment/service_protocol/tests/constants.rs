use super::super::{CredentialMutationGrant, CredentialServiceProtocolCodec};

#[test]
fn protocol_pins_the_rncred01_v2_frame_contract() {
    assert_eq!(CredentialServiceProtocolCodec::MAGIC, *b"RNCRED01");
    assert_eq!(CredentialServiceProtocolCodec::VERSION, 2);
    assert_eq!(CredentialServiceProtocolCodec::MAX_FRAME_BYTES, 16 * 1024);
    assert_eq!(
        CredentialServiceProtocolCodec::MAX_CREDENTIAL_MATERIAL_BYTES,
        4096
    );
}

#[test]
fn legacy_ownerless_v1_runtime_frame_cannot_cross_parse_as_v2() {
    let mut legacy = super::support::encoded_arm(1, 1, 1, 1, 1, 1, 1, 1, 10, 20, 8);
    legacy.drain(32..64);
    legacy[8..10].copy_from_slice(&1_u16.to_be_bytes());
    let length = u32::try_from(legacy.len() - 14).unwrap();
    legacy[10..14].copy_from_slice(&length.to_be_bytes());
    assert!(CredentialServiceProtocolCodec::decode_runtime_request(&legacy).is_err());
}

#[test]
fn grant_digest_constant_time_match_distinguishes_equal_and_different_values() {
    let expected = CredentialMutationGrant::from_wire([1; 32])
        .unwrap()
        .digest();
    let equal = CredentialMutationGrant::from_wire([1; 32])
        .unwrap()
        .digest();
    let different = CredentialMutationGrant::from_wire([2; 32])
        .unwrap()
        .digest();
    assert!(expected.ct_matches(equal));
    assert!(!expected.ct_matches(different));
}

#[test]
fn deadlines_are_bounded_to_thirty_seconds() {
    assert!(super::super::CredentialServiceDeadline::new(1, 30_001).is_ok());
    assert!(super::super::CredentialServiceDeadline::new(1, 30_002).is_err());
    assert!(super::super::CredentialServiceDeadline::new(u64::MAX, 1).is_err());
    let deadline = super::super::CredentialServiceDeadline::new(10, 20).unwrap();
    assert!(deadline.verify_parent_expiry(20).is_ok());
    assert!(deadline.verify_parent_expiry(19).is_err());
}

#[test]
fn challenge_has_no_caller_supplied_epoch() {
    let frame = CredentialServiceProtocolCodec::encode_request(
        super::super::CredentialServiceRequest::RegistrationChallenge,
    )
    .unwrap();
    assert!(matches!(
        CredentialServiceProtocolCodec::decode_desktop_request(frame.test_bytes()),
        Ok(super::super::CredentialServiceIngressRequest::RegistrationChallenge)
    ));
}
