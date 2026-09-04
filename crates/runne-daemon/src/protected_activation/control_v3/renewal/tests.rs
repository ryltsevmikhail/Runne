use super::*;
use crate::protected_activation::enrollment_v3_tests::owned_and_sessions;
use std::os::unix::net::UnixStream;

fn change_session(sessions: &Mutex<LocalSessionService>, session: [u8; 16]) {
    let mut service = sessions.lock().unwrap();
    let old = service.current_binding();
    let ephemeral = old.ephemeral();
    let next = RuntimeSessionBinding::new(
        old.stable().clone(),
        ephemeral.daemon_instance_id(),
        ephemeral.launch_generation(),
        session,
        ephemeral.authorization_epoch(),
        ephemeral.sensitivity_ceiling(),
        *old.certificate_sha256(),
    )
    .unwrap();
    *service = LocalSessionService::new_protected(
        next.clone(),
        [88; 32],
        Duration::ZERO,
        Duration::from_secs(30),
    )
    .unwrap();
}

#[test]
fn renewal_does_not_overwrite_session_changed_during_ticket_preparation() {
    let (owned, keys, sessions) = owned_and_sessions();
    let observed = Arc::clone(&sessions);
    let replacement = *uuid::Uuid::now_v7().as_bytes();
    let clock: TicketClock = Arc::new(move || {
        change_session(&observed, replacement);
        Ok(1_000)
    });
    let mut renewal =
        ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), 1, [17; 32]).unwrap();
    renewal.sign(&keys);
    let (mut peer, stream) = UnixStream::pair().unwrap();
    let mut channel = ProtectedActivationChannel::new(stream).unwrap();
    channel.enter_control_loop().unwrap();
    let session_clock: Arc<dyn Fn() -> Duration + Send + Sync> =
        Arc::new(|| Duration::from_secs(1));
    assert!(
        rotate(
            &mut channel,
            &keys,
            &owned,
            &sessions,
            &session_clock,
            &clock,
            &renewal,
            0
        )
        .is_err()
    );
    let service = sessions.lock().unwrap();
    assert_eq!(
        service.current_binding().ephemeral().session_id(),
        &replacement
    );
    drop(service);
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn renewal_rejects_already_replaced_session_before_preparing_or_publishing_ticket() {
    let (owned, keys, sessions) = owned_and_sessions();
    change_session(&sessions, *uuid::Uuid::now_v7().as_bytes());
    let before = sessions.lock().unwrap().current_binding().clone();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let clock: TicketClock = Arc::new(move || {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(1_000)
    });
    let mut renewal =
        ProtectedCredentialEnrollmentRenewRequestV3::new(owned.clone(), 1, [17; 32]).unwrap();
    renewal.sign(&keys);
    let (mut peer, stream) = UnixStream::pair().unwrap();
    let mut channel = ProtectedActivationChannel::new(stream).unwrap();
    channel.enter_control_loop().unwrap();
    let session_clock: Arc<dyn Fn() -> Duration + Send + Sync> =
        Arc::new(|| Duration::from_secs(1));
    assert!(matches!(
        rotate(
            &mut channel,
            &keys,
            &owned,
            &sessions,
            &session_clock,
            &clock,
            &renewal,
            0,
        ),
        Err(LaunchAuthorityError::OwnershipMismatch)
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(sessions.lock().unwrap().current_binding(), &before);
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
