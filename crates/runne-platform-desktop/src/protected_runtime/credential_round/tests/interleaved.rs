use super::*;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn async_round_rejects_missing_terminal_or_renewal_without_consuming_old_facts() {
    for terminal in [false, true] {
        let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
        let process = supervisor.process.as_mut().unwrap();
        process.enrollment_broker_facts = Some(EnrollmentBrokerFacts::new([31; 32], [32; 32]));
        if terminal {
            process.record_enrollment_terminal().unwrap();
        }
        let supervisor = Arc::new(Mutex::new(supervisor));
        let result =
            ProtectedBundledRuntimeSupervisor::begin_next_protected_credential_round_with_rejoin(
                Arc::clone(&supervisor),
            )
            .await;
        let mut guard = supervisor.lock().unwrap();
        let process = guard.process.as_mut().unwrap();
        process.child.kill().unwrap();
        process.child.wait().unwrap();
        let preserved = process.enrollment_broker_facts.is_some();
        let fenced = process.graceful_requested;
        drop(guard);
        assert!(result.is_err());
        assert!(preserved);
        assert!(!fenced);
    }
}

#[tokio::test]
async fn async_round_fences_tampered_offer_without_restoring_previous_broker() {
    let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    let process = supervisor.process.as_mut().unwrap();
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!()
    };
    let mut codec = ProtectedCredentialRoundCodec::new(&process.keys, owned);
    let mut facts = EnrollmentBrokerFacts::new([31; 32], [32; 32]);
    facts.terminal_session = Some([77; 16]);
    process.enrollment_broker_facts = Some(facts);
    let (channel, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    process.channel = channel;
    let daemon = std::thread::spawn(move || {
        codec
            .decode_request(&read_frame(&mut peer).unwrap())
            .unwrap();
        let mut offer = codec
            .encode_offer(ProtectedCredentialRoundBrokerFacts::new([41; 32], [42; 32]).unwrap())
            .unwrap();
        *offer.last_mut().unwrap() ^= 1;
        write_frame(&mut peer, &offer).unwrap();
        read_frame(&mut peer).is_err()
    });
    let supervisor = Arc::new(Mutex::new(supervisor));
    let result =
        ProtectedBundledRuntimeSupervisor::begin_next_protected_credential_round_with_rejoin(
            Arc::clone(&supervisor),
        )
        .await;
    let mut guard = supervisor.lock().unwrap();
    let process = guard.process.as_mut().unwrap();
    let _ = process.child.kill();
    process.child.wait().unwrap();
    let absent = process.enrollment_broker_facts.is_none();
    let fenced = process.graceful_requested;
    drop(guard);
    assert!(daemon.join().unwrap());
    assert!(result.is_err());
    assert!(absent && fenced);
}

#[tokio::test]
async fn async_round_installs_new_broker_only_after_authenticated_offer_and_accept() {
    let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    let process = supervisor.process.as_mut().unwrap();
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!()
    };
    let mut codec = ProtectedCredentialRoundCodec::new(&process.keys, owned);
    let mut facts = EnrollmentBrokerFacts::new([31; 32], [32; 32]);
    facts.terminal_session = Some([77; 16]);
    process.enrollment_broker_facts = Some(facts);
    let (channel, mut peer) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    process.channel = channel;
    let daemon = std::thread::spawn(move || {
        let Ok(request) = read_frame(&mut peer) else {
            return false;
        };
        codec.decode_request(&request).unwrap();
        write_frame(
            &mut peer,
            &codec
                .encode_offer(ProtectedCredentialRoundBrokerFacts::new([41; 32], [42; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        codec.decode_accept(&read_frame(&mut peer).unwrap()).is_ok()
    });
    let supervisor = Arc::new(Mutex::new(supervisor));
    let result =
        ProtectedBundledRuntimeSupervisor::begin_next_protected_credential_round_with_rejoin(
            Arc::clone(&supervisor),
        )
        .await;
    let facts = {
        let mut guard = supervisor.lock().unwrap();
        let process = guard.process.as_mut().unwrap();
        let _ = process.child.kill();
        process.child.wait().unwrap();
        let facts = process.enrollment_broker_facts;
        drop(guard);
        facts
    };
    let accepted = daemon.join().unwrap();
    result.unwrap();
    assert!(accepted);
    let facts = facts.unwrap();
    assert_eq!(facts.binding(), [41; 32]);
    assert_eq!(facts.publication_public_key(), [42; 32]);
    assert_eq!(facts.terminal_session, None);
}
