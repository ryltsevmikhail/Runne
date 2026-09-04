use super::*;
use crate::protected_runtime::{
    BundledRuntimeLifecycleState, ProtectedProcessActivation, read_frame,
    test_only_ready_v3_enrollment_supervisor, write_frame,
};
use runne_api::{
    ProtectedCredentialEnrollmentRenewRequestV3, ProtectedCredentialEnrollmentRenewTicketV3,
};
use std::{os::unix::net::UnixStream, time::Duration};
mod rejection;

#[tokio::test]
async fn async_renewal_installs_only_a_verified_current_ticket() {
    let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    let process = supervisor.process.as_mut().unwrap();
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!()
    };
    let previous = *owned.session_id();
    let (channel, mut peer) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    process.channel = channel;
    let next = *uuid::Uuid::now_v7().as_bytes();
    let daemon = std::thread::spawn(move || {
        let Ok(frame) = read_frame(&mut peer) else {
            return false;
        };
        let request = ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&frame).unwrap();
        let keys = runne_api::LaunchSecret::from_bytes([3; 32])
            .unwrap()
            .derive_keys();
        let mut ticket =
            ProtectedCredentialEnrollmentRenewTicketV3::new(&request, next, [24; 32], 100, 200)
                .unwrap();
        ticket.sign(&keys);
        write_frame(&mut peer, &ticket.encode_frame().unwrap()).unwrap();
        true
    });
    let supervisor = Arc::new(Mutex::new(supervisor));
    let result = queue_with_clock(Arc::clone(&supervisor), || Ok(100)).await;
    let mut guard = supervisor.lock().unwrap();
    let process = guard.process.as_mut().unwrap();
    let _ = process.child.kill();
    process.child.wait().unwrap();
    let sequence = process.renewal_sequence;
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!()
    };
    let current = *owned.session_id();
    let queued = guard.pending_profile.is_some();
    let state = guard.state;
    drop(guard);
    let sent = daemon.join().unwrap();
    result.unwrap();
    assert!(sent && queued);
    assert_ne!(current, previous);
    assert_eq!(current, next);
    assert_eq!(sequence, 1);
    assert_eq!(state, BundledRuntimeLifecycleState::Handshaking);
}
