use super::super::CredentialServiceProtocolCodec;

#[test]
fn protocol_pins_the_rncred01_v1_frame_contract() {
    assert_eq!(CredentialServiceProtocolCodec::MAGIC, *b"RNCRED01");
    assert_eq!(CredentialServiceProtocolCodec::VERSION, 1);
    assert_eq!(CredentialServiceProtocolCodec::MAX_FRAME_BYTES, 16 * 1024);
    assert_eq!(
        CredentialServiceProtocolCodec::MAX_CREDENTIAL_MATERIAL_BYTES,
        4096
    );
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
