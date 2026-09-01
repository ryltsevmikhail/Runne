use super::*;

fn legacy_owned() -> (
    runne_api::ProtectedOwnedLaunchV1,
    runne_api::ProtectedActivationKeys,
) {
    let (request, _, keys, _) = launch();
    let stable =
        StableRuntimeBindingV1::new(id(10), "local-owner", id(11), "fixture", [1; 32], [2; 32])
            .unwrap();
    let ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        request.executable().clone(),
        profile(),
        stable,
        id(12),
        1,
        id(13),
        "https://127.0.0.1",
        [14; 32],
        vec![15],
        vec!["provider.enroll".into()],
    )
    .unwrap();
    (ready.owned_launch(), keys)
}

#[test]
fn v3_control_rejects_v1_and_v2_renewal_and_shutdown_frames() {
    let (legacy, keys) = legacy_owned();
    let mut v1_renewal = ProtectedRenewRequestV1::new(legacy.clone(), 1, [21; 32]).unwrap();
    v1_renewal.sign(&keys);
    let mut v1_shutdown = ProtectedShutdownV1::new(legacy.clone());
    v1_shutdown.sign(&keys);
    let v2 = ProtectedOwnedLaunchV2::new(
        legacy,
        ProviderActivationBindingV1::openai_responses_text_v1(),
    )
    .unwrap();
    let mut v2_renewal = ProtectedRenewRequestV2::new(v2.clone(), 1, [22; 32]).unwrap();
    v2_renewal.sign(&keys);
    let mut v2_shutdown = ProtectedShutdownV2::new(v2);
    v2_shutdown.sign(&keys);
    for frame in [
        v1_renewal.encode_frame().unwrap(),
        v1_shutdown.encode_frame().unwrap(),
        v2_renewal.encode_frame().unwrap(),
        v2_shutdown.encode_frame().unwrap(),
    ] {
        let (owned, keys, sessions) = owned_and_sessions();
        let (mut client, server) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            run_control_loop_v3(
                ProtectedActivationChannel::new(server).unwrap(),
                keys,
                owned,
                sessions,
                Arc::new(|| Duration::from_secs(1)),
                Arc::new(|| Ok(1_000)),
                super::super::enrollment_control_transition::DaemonEnrollmentRendezvous::for_test(),
            )
        });
        client.write_all(&frame).unwrap();
        assert_eq!(
            server.join().unwrap(),
            Err(runne_api::LaunchAuthorityError::InvalidContract)
        );
    }
}
