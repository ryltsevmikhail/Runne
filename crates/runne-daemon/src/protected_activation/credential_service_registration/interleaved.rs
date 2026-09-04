use super::*;
use zeroize::Zeroizing;

pub(super) struct RejoinFrames {
    pub claim: Zeroizing<Vec<u8>>,
    pub acknowledgement: Zeroizing<Vec<u8>>,
    pub deferred: Option<Zeroizing<Vec<u8>>>,
}

pub(super) fn receive(
    channel: &mut ProtectedActivationChannel,
) -> Result<RejoinFrames, LaunchAuthorityError> {
    let first = channel.read_control_frame()?;
    let (claim, deferred) = if is_crossed_exchange(&first) {
        (channel.read_control_frame()?, Some(first))
    } else {
        (first, None)
    };
    if is_crossed_exchange(&claim) {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    Ok(RejoinFrames {
        claim,
        acknowledgement: channel.read_control_frame()?,
        deferred,
    })
}

// Routing only: deferred bytes retain all authentication and lifecycle checks
// in the normal V3 dispatcher. Never execute a crossed request during rejoin.
fn is_crossed_exchange(frame: &[u8]) -> bool {
    runne_api::ProtectedCredentialDiscoveryCodec::recognizes_frame(frame)
        || runne_api::ProtectedCredentialRoundCodec::recognizes_frame(frame)
        || runne_api::ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(frame).is_ok()
        || runne_api::ProtectedCredentialEnrollmentShutdownV3::decode_frame(frame).is_ok()
        || runne_api::is_broker_handoff_frame(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protected_activation::enrollment_v3_tests::owned_and_sessions;
    use std::os::unix::net::UnixStream;

    #[test]
    fn rejoin_defers_broker_offer_without_consuming_it_as_registration() {
        let (_, keys, _) = owned_and_sessions();
        let auth =
            runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let context =
            runne_api::ProviderCredentialBrokerHandoffContext::new([1; 16], [2; 16], 3, [4; 32])
                .unwrap();
        for purpose in [1, 2, 3] {
            let offer = runne_api::ProviderCredentialBrokerHandoffFrame::offer(
                context.clone(),
                purpose,
                100,
                300,
                [7; 16],
                &auth,
            )
            .unwrap()
            .encode_frame();
            let (peer, stream) = UnixStream::pair().unwrap();
            let mut peer = ProtectedActivationChannel::new(peer).unwrap();
            let mut channel = ProtectedActivationChannel::new(stream).unwrap();
            let claim = [0, 0, 0, 1, 21];
            let ack = [0, 0, 0, 1, 22];
            peer.write_control_frame(&offer).unwrap();
            peer.write_control_frame(&claim).unwrap();
            peer.write_control_frame(&ack).unwrap();
            let frames = receive(&mut channel).unwrap();
            assert_eq!(frames.claim.as_slice(), claim);
            assert_eq!(frames.acknowledgement.as_slice(), ack);
            assert_eq!(frames.deferred.unwrap().as_slice(), offer.as_slice());
        }
    }

    #[test]
    fn rejoin_without_crossed_request_keeps_registration_order() {
        let (peer, stream) = UnixStream::pair().unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        let mut channel = ProtectedActivationChannel::new(stream).unwrap();
        let claim = [0, 0, 0, 1, 21];
        let ack = [0, 0, 0, 1, 22];
        peer.write_control_frame(&claim).unwrap();
        peer.write_control_frame(&ack).unwrap();
        let frames = receive(&mut channel).unwrap();
        assert_eq!(frames.claim.as_slice(), claim);
        assert_eq!(frames.acknowledgement.as_slice(), ack);
        assert!(frames.deferred.is_none());
    }

    #[test]
    fn rejoin_rejects_a_second_crossed_request_without_waiting_for_registration() {
        let (owned, keys, _) = owned_and_sessions();
        let request = runne_api::ProtectedCredentialDiscoveryCodec::new(&keys, &owned)
            .encode_request([7; 32])
            .unwrap();
        let (peer, stream) = UnixStream::pair().unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        let mut channel = ProtectedActivationChannel::new(stream).unwrap();
        peer.write_control_frame(&request).unwrap();
        peer.write_control_frame(&request).unwrap();
        drop(peer);
        assert!(matches!(
            receive(&mut channel),
            Err(LaunchAuthorityError::InvalidContract)
        ));
    }

    #[test]
    fn rejoin_preserves_one_crossed_discovery_for_normal_dispatch() {
        let (owned, keys, _) = owned_and_sessions();
        let request = runne_api::ProtectedCredentialDiscoveryCodec::new(&keys, &owned)
            .encode_request([7; 32])
            .unwrap();
        let (peer, stream) = UnixStream::pair().unwrap();
        let mut peer = ProtectedActivationChannel::new(peer).unwrap();
        let mut channel = ProtectedActivationChannel::new(stream).unwrap();
        peer.write_control_frame(&request).unwrap();
        // Exact payload bytes are later authenticated by accept_registration_frames.
        let claim = [0, 0, 0, 1, 21];
        let ack = [0, 0, 0, 1, 22];
        peer.write_control_frame(&claim).unwrap();
        peer.write_control_frame(&ack).unwrap();
        let frames = receive(&mut channel).unwrap();
        assert_eq!(frames.claim.as_slice(), claim);
        assert_eq!(frames.acknowledgement.as_slice(), ack);
        assert_eq!(frames.deferred.unwrap().as_slice(), request.as_slice());
    }
}
