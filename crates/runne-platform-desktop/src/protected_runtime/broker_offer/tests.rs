use super::*;
use std::{os::unix::net::UnixStream, time::Duration};

#[test]
fn kill_ack_requires_live_receipt_clock_and_correct_phase() {
    for (tick, wrong_phase, accepted) in [
        (Some(300), false, true),
        (Some(301), false, false),
        (Some(99), false, false),
        (None, false, false),
        (Some(200), true, false),
    ] {
        let keys = runne_api::LaunchSecret::from_bytes([3; 32])
            .unwrap()
            .derive_keys();
        let auth = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let context =
            ProviderCredentialBrokerHandoffContext::new([1; 16], [2; 16], 3, [4; 32]).unwrap();
        let offer = ProviderCredentialBrokerHandoffFrame::offer(
            context.clone(),
            ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
            100,
            300,
            [7; 16],
            &auth,
        )
        .unwrap();
        let frame = if wrong_phase {
            offer.ready(&auth)
        } else {
            offer.acknowledgement(&auth)
        };
        let (mut channel, mut peer) = UnixStream::pair().unwrap();
        write_frame(&mut peer, &frame.encode_frame()).unwrap();
        let result = receive(
            &mut channel,
            &context,
            &auth,
            ProviderCredentialBrokerHandoffFrame::PHASE_ACK,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_KILL,
            [7; 16],
            || tick.ok_or(ProtectedBundledRuntimeError::ProtectedChannelUnavailable),
        );
        assert_eq!(result.is_ok(), accepted);
    }
}

#[test]
fn broker_ready_must_still_be_live_when_received() {
    for (received_at, accepted) in [(100, true), (30_099, true), (30_100, true), (30_101, false)] {
        let keys = runne_api::LaunchSecret::from_bytes([3; 32])
            .unwrap()
            .derive_keys();
        let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let context =
            ProviderCredentialBrokerHandoffContext::new([1; 16], [2; 16], 3, [4; 32]).unwrap();
        let (mut channel, mut peer) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let peer_context = context.clone();
        let daemon = std::thread::spawn(move || {
            let auth = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
            let offer = ProviderCredentialBrokerHandoffFrame::decode_and_verify(
                &read_frame(&mut peer).unwrap(),
                &auth,
                &peer_context,
                ProviderCredentialBrokerHandoffFrame::PHASE_OFFER,
                ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
                [0; 16],
                100,
            )
            .unwrap();
            write_frame(&mut peer, &offer.ready(&auth).encode_frame()).unwrap();
        });
        let mut clock = [100, received_at].into_iter();
        let result = exchange(
            &mut channel,
            &context,
            &authenticator,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
            || Ok(clock.next().expect("bounded clock reads")),
        );
        daemon.join().unwrap();
        assert_eq!(result.is_ok(), accepted, "receipt tick {received_at}");
    }
}
