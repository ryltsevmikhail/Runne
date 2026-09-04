use super::*;
use crate::protected_activation::enrollment_v3_tests::owned_and_sessions;

#[test]
fn round_without_trusted_profile_context_closes_without_offer_or_rotation() {
    use std::os::unix::net::UnixStream;
    let (owned, keys, sessions) = owned_and_sessions();
    let observed = Arc::clone(&sessions);
    let expected = sessions.lock().unwrap().current_binding().clone();
    let request = runne_api::ProtectedCredentialRoundCodec::new(&keys, &owned)
        .encode_request([19; 32])
        .unwrap();
    let (mut peer, stream) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let server = std::thread::spawn(move || {
        run_control_loop_v3(ProtectedActivationChannel::new(stream).unwrap(), keys, owned,
            sessions, Arc::new(|| Duration::from_secs(1)), Arc::new(|| Ok(1_000)),
            crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous::for_test())
    });
    peer.write_all(&request).unwrap();
    assert_eq!(
        server.join().unwrap(),
        Err(LaunchAuthorityError::OwnershipMismatch)
    );
    assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    assert_eq!(observed.lock().unwrap().current_binding(), &expected);
}

#[test]
fn round_requires_a_different_session_from_verified_renewal() {
    let (previous, keys, _) = owned_and_sessions();
    assert!(require_successor(&previous, &previous).is_err());
    let mut request =
        ProtectedCredentialEnrollmentRenewRequestV3::new(previous.clone(), 1, [17; 32]).unwrap();
    request.sign(&keys);
    let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
        &request,
        *uuid::Uuid::now_v7().as_bytes(),
        [18; 32],
        1_000,
        31_000,
    )
    .unwrap();
    ticket.sign(&keys);
    let next = ticket
        .verify_exact_at(&request, 1_000, &keys)
        .unwrap()
        .next_owned_launch();
    assert_eq!(require_successor(&previous, &next), Ok(()));
    assert!(require_successor(&next, &next).is_err());
}
