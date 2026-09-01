use zeroize::Zeroizing;

use crate::{CredentialSecretClaimOffer, CredentialSecretRelayFrameCodec};

use super::super::relay_frame::AuthenticatedCredentialSecretRelaySealer;
use super::{authorization, binding, channel, channel_from, command};

#[test]
fn authenticated_relay_seals_only_exact_signed_offer_for_rendezvous() {
    let command = command(80);
    let claim = binding(81);
    let (offer, pending) = CredentialSecretClaimOffer::prepare(&command, claim).unwrap();
    let channel = channel();
    let (public_key, publication) =
        super::super::publication::fixture_publication(&offer, &channel);
    let frame = CredentialSecretRelayFrameCodec::encode(&offer, &publication);
    let envelope = AuthenticatedCredentialSecretRelaySealer::from_authenticated_rendezvous(
        public_key,
        channel.digest().as_bytes(),
    )
    .unwrap()
    .seal(&frame, Zeroizing::new(b"credential".to_vec()))
    .unwrap();
    let (authorization, channel) = authorization(&command, claim);
    let material = pending
        .open_after_claim(authorization, &channel, envelope)
        .unwrap();
    material
        .consume(|value| {
            assert_eq!(value, b"credential");
            Ok::<_, ()>(())
        })
        .unwrap();
}

#[test]
fn authenticated_relay_rejects_wrong_key_channel_and_tamper() {
    let command = command(82);
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding(83)).unwrap();
    let channel = channel();
    let (public_key, publication) =
        super::super::publication::fixture_publication(&offer, &channel);
    let frame = CredentialSecretRelayFrameCodec::encode(&offer, &publication);

    for (key, binding) in [
        ([9; 32], channel.digest().as_bytes()),
        (public_key, channel_from([9; 32]).digest().as_bytes()),
    ] {
        assert!(
            AuthenticatedCredentialSecretRelaySealer::from_authenticated_rendezvous(key, binding)
                .unwrap()
                .seal(&frame, Zeroizing::new(b"credential".to_vec()))
                .is_err()
        );
    }
    for offset in [0, 12, CredentialSecretRelayFrameCodec::BYTES - 1] {
        let mut tampered = frame;
        tampered[offset] ^= 1;
        assert!(
            AuthenticatedCredentialSecretRelaySealer::from_authenticated_rendezvous(
                public_key,
                channel.digest().as_bytes(),
            )
            .unwrap()
            .seal(&tampered, Zeroizing::new(b"credential".to_vec()))
            .is_err()
        );
    }
}
