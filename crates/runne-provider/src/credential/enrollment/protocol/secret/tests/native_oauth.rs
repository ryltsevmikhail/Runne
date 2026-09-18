use super::{authorization, binding, oauth_command, verified_offer};
use crate::CredentialSecretEnvelopeCodec;
use zeroize::Zeroizing;

#[test]
fn native_oauth_relay_accepts_32k_and_legacy_codec_rejects_it() {
    let command = oauth_command(14);
    let binding = binding(15);
    let (accepted, pending) = verified_offer(&command, binding);
    let credential = vec![b'o'; 32 * 1024];
    let envelope = accepted
        .seal_native_oauth(Zeroizing::new(credential.clone()))
        .unwrap();
    assert!(CredentialSecretEnvelopeCodec::encode(&envelope).is_err());
    let encoded = CredentialSecretEnvelopeCodec::encode_native_oauth(&envelope).unwrap();
    assert!(encoded.len() > CredentialSecretEnvelopeCodec::MAX_BYTES);
    let decoded = CredentialSecretEnvelopeCodec::decode(&encoded).unwrap();
    let (authorization, channel) = authorization(&command, binding);
    let opened = pending
        .open_after_claim(authorization, &channel, decoded)
        .unwrap();
    opened
        .consume(|bytes| {
            assert_eq!(bytes, credential);
            Ok::<_, ()>(())
        })
        .unwrap();
}
