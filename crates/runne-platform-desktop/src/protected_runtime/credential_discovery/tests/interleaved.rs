use super::*;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn async_discovery_preserves_authenticated_response_and_rejects_tampering() {
    for tamper in [false, true] {
        let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
        let process = supervisor.process.as_mut().unwrap();
        let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
            panic!()
        };
        let mut codec = runne_api::ProtectedCredentialDiscoveryCodec::new(&process.keys, owned);
        let mut facts = EnrollmentBrokerFacts::new([31; 32], [32; 32]);
        facts.terminal_session = Some(*owned.session_id());
        process.enrollment_broker_facts = Some(facts);
        let (channel, mut peer) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        process.channel = channel;
        let peer = std::thread::spawn(move || {
            codec
                .decode_request(&read_frame(&mut peer).unwrap())
                .unwrap();
            let mut response = codec.encode_response(&[[7; 16], [8; 16]]).unwrap();
            if tamper {
                *response.last_mut().unwrap() ^= 1;
            }
            write_frame(&mut peer, &response).unwrap();
        });
        let supervisor = Arc::new(Mutex::new(supervisor));
        let result =
            ProtectedBundledRuntimeSupervisor::discover_prepared_credential_cleanup_with_rejoin(
                Arc::clone(&supervisor),
            )
            .await;
        {
            let mut guard = supervisor.lock().unwrap();
            let process = guard.process.as_mut().unwrap();
            let _ = process.child.kill();
            process.child.wait().unwrap();
            drop(guard);
        }
        peer.join().unwrap();
        if tamper {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), vec![[7; 16], [8; 16]]);
        }
    }
}
