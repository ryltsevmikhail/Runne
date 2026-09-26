use super::super::*;
use runne_api::{LaunchSecret, ProtectedCredentialEnrollmentLifecycleCodec};

#[test]
fn production_lifecycle_frame_binds_fd_offer_not_its_decoded_payload() {
    let authenticator = super::setup();
    let keys = LaunchSecret::from_bytes([0x43; 32]).unwrap().derive_keys();
    let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    let payload = vec![0x57; runne_api::PROTECTED_CREDENTIAL_SECRET_RELAY_BYTES];
    let frame = codec.encode_daemon_relay(&payload, 1).unwrap();
    assert_eq!(codec.decode_daemon_relay(&frame, 0).unwrap(), payload);

    let (sender, receiver) = UnixStream::pair().unwrap();
    let (relay, _reader) = super::relay();
    send(relay, &sender, &authenticator, &frame).unwrap();
    assert!(receive(&receiver, &authenticator, &frame, &[7; 32], &[8; 32]).is_ok());

    let (sender, receiver) = UnixStream::pair().unwrap();
    let (relay, _reader) = super::relay();
    send(relay, &sender, &authenticator, &frame).unwrap();
    assert!(receive(&receiver, &authenticator, &payload, &[7; 32], &[8; 32]).is_err());

    let other_frame = codec.encode_daemon_relay(&payload, 2).unwrap();
    assert_ne!(frame, other_frame);
    assert_eq!(codec.decode_daemon_relay(&other_frame, 1).unwrap(), payload);
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (relay, _reader) = super::relay();
    send(relay, &sender, &authenticator, &frame).unwrap();
    assert!(receive(&receiver, &authenticator, &other_frame, &[7; 32], &[8; 32]).is_err());
}
