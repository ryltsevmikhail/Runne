use super::*;

#[test]
fn authenticated_shutdown_ack_is_idempotent_without_second_request() {
    use std::io::Read;
    let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    let process = supervisor.process.as_mut().unwrap();
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!()
    };
    let owned = owned.clone();
    let (channel, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    process.channel = channel;
    let mut ack = runne_api::ProtectedCredentialEnrollmentShutdownAckV3::new(owned.clone(), true);
    ack.sign(&process.keys);
    write_frame(&mut peer, &ack.encode_frame().unwrap()).unwrap();
    let first = process.request_graceful_stop();
    let second = process.request_graceful_stop();
    let _ = process.child.kill();
    process.child.wait().unwrap();
    first.unwrap();
    second.unwrap();
    let frame = read_frame(&mut peer).unwrap();
    runne_api::ProtectedCredentialEnrollmentShutdownV3::decode_frame(&frame)
        .unwrap()
        .verify_exact(&owned, &process.keys)
        .unwrap();
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn fenced_child_stop_never_reports_graceful_acknowledgement() {
    for fence in [
        ProtectedBundledRuntimeProcess::fence_ambiguous_transition,
        ProtectedBundledRuntimeProcess::fence_ambiguous_v3_renewal,
    ] {
        let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
        fence(supervisor.process.as_mut().unwrap());
        assert_eq!(
            supervisor.stop().unwrap(),
            BundledRuntimeStopDisposition::Forced
        );
        assert!(supervisor.process.is_none());
        assert_eq!(supervisor.state, BundledRuntimeLifecycleState::Stopped);
    }
}
