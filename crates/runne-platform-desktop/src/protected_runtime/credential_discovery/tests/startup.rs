use super::*;
use crate::protected_runtime::{
    test_only_absent_enrollment_supervisor, v2_launch_fixture, v2_process,
};

#[test]
fn startup_discovery_skips_already_active_v3_without_channel_io() {
    let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    assert_eq!(
        supervisor.discover_startup_credential_cleanup().unwrap(),
        None
    );
    assert!(matches!(
        supervisor.process.as_ref().unwrap().activation,
        ProtectedProcessActivation::V3 { .. }
    ));
    assert_eq!(supervisor.state, BundledRuntimeLifecycleState::Ready);
}

#[test]
fn startup_discovery_preserves_v2_session_without_terminal_or_renewal() {
    for ids in [vec![], vec![[7; 16]]] {
        let (channel, mut peer) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (process, owned) = v2_process(channel);
        let expected = ids.clone();
        let daemon_owned = owned.clone();
        let daemon = std::thread::spawn(move || {
            let (_, _, keys) = v2_launch_fixture();
            let mut codec =
                runne_api::ProtectedCredentialDiscoveryCodec::for_startup(&keys, &daemon_owned);
            codec
                .decode_request(&read_frame(&mut peer).unwrap())
                .unwrap();
            write_frame(&mut peer, &codec.encode_response(&ids).unwrap()).unwrap();
        });
        let mut supervisor = test_only_absent_enrollment_supervisor().into_supervisor();
        supervisor.process = Some(process);
        supervisor.state = BundledRuntimeLifecycleState::Ready;
        let result = supervisor.discover_startup_credential_cleanup();
        // Reap the fixture even when the assertion fails.
        let retained = supervisor.process.as_mut().unwrap();
        let _ = retained.child.kill();
        let _ = retained.child.wait();
        assert_eq!(result.unwrap(), Some(expected));
        let ProtectedProcessActivation::V2 { owned: current, .. } = &retained.activation else {
            panic!("discovery changed activation")
        };
        assert_eq!(current, &owned);
        assert_eq!(retained.renewal_sequence, 0);
        assert!(retained.enrollment_broker_facts.is_none());
        assert!(supervisor.pending_profile.is_none());
        daemon.join().unwrap();
    }
}
