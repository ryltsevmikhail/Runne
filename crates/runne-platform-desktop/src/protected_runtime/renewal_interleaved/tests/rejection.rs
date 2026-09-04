use super::*;

#[tokio::test]
async fn async_renewal_fences_bad_or_expired_ticket_without_advancing_owned_state() {
    for (now, tamper) in [
        (Some(99), false),
        (Some(201), false),
        (None, false),
        (Some(100), true),
    ] {
        let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
        let process = supervisor.process.as_mut().unwrap();
        let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
            panic!()
        };
        let previous = owned.clone();
        let (channel, mut peer) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        process.channel = channel;
        let daemon = std::thread::spawn(move || {
            let request = ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(
                &read_frame(&mut peer).unwrap(),
            )
            .unwrap();
            let keys = runne_api::LaunchSecret::from_bytes([3; 32])
                .unwrap()
                .derive_keys();
            let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
                &request,
                *uuid::Uuid::now_v7().as_bytes(),
                [24; 32],
                100,
                200,
            )
            .unwrap();
            ticket.sign(&keys);
            let mut frame = ticket.encode_frame().unwrap();
            if tamper {
                *frame.last_mut().unwrap() ^= 1;
            }
            write_frame(&mut peer, &frame).unwrap();
        });
        let supervisor = Arc::new(Mutex::new(supervisor));
        let result = queue_with_clock(Arc::clone(&supervisor), move || {
            now.ok_or(ProtectedBundledRuntimeError::InvalidState)
        })
        .await;
        let mut guard = supervisor.lock().unwrap();
        let process = guard.process.as_mut().unwrap();
        let _ = process.child.kill();
        process.child.wait().unwrap();
        let sequence = process.renewal_sequence;
        let fenced = process.graceful_requested;
        let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
            panic!()
        };
        let unchanged = owned == &previous;
        let empty = guard.pending_profile.is_none();
        drop(guard);
        daemon.join().unwrap();
        assert!(result.is_err());
        assert!(fenced && unchanged && empty);
        assert_eq!(sequence, 0);
    }
}
