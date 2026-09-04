use super::super::{
    EnrollmentBrokerFacts, ProtectedProcessActivation, test_only_ready_v3_enrollment_supervisor,
};
use super::*;
use std::{os::unix::net::UnixStream, time::Duration};
mod interleaved;
mod startup;

#[test]
fn desktop_discovery_rejects_nonterminal_or_other_terminal_session_before_io() {
    for marker in [None, Some([77; 16])] {
        let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
        let process = supervisor.process.as_mut().unwrap();
        let mut facts = EnrollmentBrokerFacts::new([31; 32], [32; 32]);
        facts.terminal_session = marker;
        process.enrollment_broker_facts = Some(facts);
        assert!(matches!(
            supervisor.discover_prepared_credential_cleanup(),
            Err(ProtectedBundledRuntimeError::InvalidState)
        ));
        assert_eq!(
            supervisor
                .process
                .as_ref()
                .unwrap()
                .enrollment_broker_facts
                .unwrap()
                .terminal_session,
            marker
        );
        assert_eq!(supervisor.state, BundledRuntimeLifecycleState::Ready);
    }
}

#[test]
fn desktop_discovery_returns_only_authenticated_current_request_ids() {
    let supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    let ProtectedProcessActivation::V3 { owned, .. } =
        &supervisor.process.as_ref().unwrap().activation
    else {
        panic!()
    };
    for tamper in [false, true] {
        let owned = owned.clone();
        let daemon_owned = owned.clone();
        let (mut channel, mut peer) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let daemon = std::thread::spawn(move || {
            let keys = runne_api::LaunchSecret::from_bytes([41; 32])
                .unwrap()
                .derive_keys();
            let mut codec = runne_api::ProtectedCredentialDiscoveryCodec::new(&keys, &daemon_owned);
            let request = read_frame(&mut peer).unwrap();
            codec.decode_request(&request).unwrap();
            let mut response = codec.encode_response(&[[7; 16], [8; 16]]).unwrap();
            if tamper {
                *response.last_mut().unwrap() ^= 1;
            }
            write_frame(&mut peer, &response).unwrap();
        });
        let keys = runne_api::LaunchSecret::from_bytes([41; 32])
            .unwrap()
            .derive_keys();
        let result = exchange(&mut channel, &keys, &owned);
        if tamper {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), vec![[7; 16], [8; 16]]);
        }
        daemon.join().unwrap();
    }
}
