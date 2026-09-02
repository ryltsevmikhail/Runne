use runne_api::{
    CREDENTIAL_SERVICE_MAX_FRAME_BYTES, CREDENTIAL_SERVICE_RUNTIME_PROVIDER_FRAME_MAX_BYTES,
    CredentialServiceSessionAuthenticator, LaunchSecret,
};
use runne_provider::CredentialServiceProtocolCodec;

#[test]
fn exact_runtime_provider_ceiling_fills_one_authenticated_outer_frame() {
    assert_eq!(
        CredentialServiceProtocolCodec::MAX_RUNTIME_PROVIDER_FRAME_BYTES,
        CREDENTIAL_SERVICE_RUNTIME_PROVIDER_FRAME_MAX_BYTES,
    );
    let mut inner = vec![0_u8; CREDENTIAL_SERVICE_RUNTIME_PROVIDER_FRAME_MAX_BYTES];
    let payload_len = (inner.len() - 14) as u32;
    inner[..8].copy_from_slice(b"RNCRED01");
    inner[8..10].copy_from_slice(&2_u16.to_be_bytes());
    inner[10..14].copy_from_slice(&payload_len.to_be_bytes());
    CredentialServiceProtocolCodec::validate_runtime_provider_frame(&inner).unwrap();

    let auth = CredentialServiceSessionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys(),
    );
    let owner = [9_u8; 32];
    let envelope = auth.authenticate_runtime_request(owner, &inner).unwrap();
    let mut outer = Vec::new();
    envelope
        .send(|bytes| {
            outer.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(outer.len(), CREDENTIAL_SERVICE_MAX_FRAME_BYTES);
    let verified = auth.verify_runtime_request(owner, &outer).unwrap();
    let mut inner_valid = false;
    verified.consume(|bytes| {
        inner_valid = CredentialServiceProtocolCodec::validate_runtime_provider_frame(bytes).is_ok()
    });
    assert!(inner_valid);

    inner.push(0);
    assert!(CredentialServiceProtocolCodec::validate_runtime_provider_frame(&inner).is_err());
    assert!(auth.authenticate_runtime_request(owner, &inner).is_err());
}
