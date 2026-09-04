use super::*;
use std::os::unix::net::UnixStream;
mod crossed;
mod crossed_broker;
mod crossed_renewal;
mod crossed_round;
mod crossed_shutdown;
mod gateway_terminal;

#[test]
fn crossed_broker_offer_is_released_only_after_authenticated_registration() {
    for corrupt_ack in [false, true] {
        let (keys, binding, claim, mut ack) = evidence();
        let auth =
            runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let context =
            runne_api::ProviderCredentialBrokerHandoffContext::new([1; 16], [2; 16], 3, [4; 32])
                .unwrap();
        let offer = runne_api::ProviderCredentialBrokerHandoffFrame::offer(
            context.clone(),
            1,
            90,
            120,
            [7; 16],
            &auth,
        )
        .unwrap()
        .encode_frame();
        if corrupt_ack {
            *ack.last_mut().unwrap() ^= 1;
        }
        let (peer, stream) = UnixStream::pair().unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        let mut channel = ProtectedActivationChannel::new(stream).unwrap();
        peer.write_control_frame(&offer).unwrap();
        peer.write_control_frame(&claim).unwrap();
        peer.write_control_frame(&ack).unwrap();
        let expected = ExpectedCredentialServiceRegistration::from_binding(&binding);
        let result = receive(
            &mut channel,
            &keys,
            &expected,
            99,
            interleaved::receive,
            || Ok(99),
        );
        if corrupt_ack {
            assert!(
                result.is_err(),
                "invalid service ACK cannot release broker authority"
            );
        } else {
            let deferred = result.unwrap().deferred.unwrap();
            assert_eq!(deferred.as_slice(), offer.as_slice());
            runne_api::ProviderCredentialBrokerHandoffFrame::decode_and_verify(
                &deferred,
                &auth,
                &context,
                runne_api::ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
                1,
                [0; 16],
                99,
            )
            .unwrap();
        }
    }
}

#[test]
fn registration_receipt_accepts_live_evidence_but_never_rolls_time_back() {
    for (minimum, observed, accepted) in [
        (99, Some(99), true),
        (100, Some(99), false),
        (99, Some(100), false),
        (99, None, false),
    ] {
        let (keys, binding, claim, ack) = evidence();
        let expected = ExpectedCredentialServiceRegistration::from_binding(&binding);
        let (peer, stream) = UnixStream::pair().unwrap();
        let mut channel = ProtectedActivationChannel::new(stream).unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        peer.write_control_frame(&claim).unwrap();
        peer.write_control_frame(&ack).unwrap();
        let result = receive(&mut channel, &keys, &expected, minimum, initial, || {
            observed.ok_or(LaunchAuthorityError::InvalidContract)
        });
        assert_eq!(result.is_ok(), accepted);
    }
}

#[test]
fn registration_expiring_during_read_is_rejected_at_receipt() {
    for read in [initial, interleaved::receive] {
        let (keys, binding, claim, ack) = evidence();
        let expected = ExpectedCredentialServiceRegistration::from_binding(&binding);
        let (peer, stream) = UnixStream::pair().unwrap();
        let observer = ProtectedActivationChannel::new(stream.try_clone().unwrap()).unwrap();
        let mut channel = ProtectedActivationChannel::new(stream).unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        peer.write_control_frame(&claim).unwrap();
        peer.write_control_frame(&ack).unwrap();
        let result = receive(&mut channel, &keys, &expected, 99, read, || {
            // A deterministic clock boundary: 99 before reads, expiry 100 after reads.
            Ok(if observer.control_frame_ready()? {
                99
            } else {
                100
            })
        });
        assert!(
            result.is_err(),
            "expired receipt must not install a service session"
        );
    }
}

fn evidence() -> (
    ProtectedActivationKeys,
    CredentialServiceRegistrationBinding,
    Vec<u8>,
    Vec<u8>,
) {
    let keys = runne_api::LaunchSecret::from_bytes([7; 32])
        .unwrap()
        .derive_keys();
    let binding = CredentialServiceRegistrationBinding::new(
        [9; 16],
        *uuid::Uuid::now_v7().as_bytes(),
        11,
        11,
        13,
        14,
        [3; 32],
        [4; 32],
        [6; 16],
        2,
        100,
    )
    .unwrap();
    let auth = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
    let claim = auth
        .authenticate_registration(binding.clone())
        .unwrap()
        .into_bytes();
    let verified = auth
        .decode_and_verify_registration_for(&claim, &binding, 99)
        .unwrap();
    let ack = auth.registration_ack(verified, 99).unwrap().into_bytes();
    let frame = |bytes: Vec<u8>| {
        let mut framed = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        framed.extend(bytes);
        framed
    };
    (keys, binding, frame(claim), frame(ack))
}
