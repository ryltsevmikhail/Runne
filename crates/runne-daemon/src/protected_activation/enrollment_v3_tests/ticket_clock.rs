use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac as _};
use runne_application::local_session::{BootstrapProof, bootstrap_proof_transcript};
use sha2::Sha256;

use super::{
    ProtectedActivationChannel, ProtectedCredentialEnrollmentRenewRequestV3,
    ProtectedCredentialEnrollmentRenewTicketV3, ProtectedCredentialEnrollmentShutdownAckV3,
    ProtectedCredentialEnrollmentShutdownV3, owned_and_sessions, read_frame, run_control_loop_v3,
};

type HmacSha256 = Hmac<Sha256>;

fn authenticate_existing_session(
    sessions: &Arc<std::sync::Mutex<runne_application::local_session::LocalSessionService>>,
) -> runne_api::RuntimeSessionBinding {
    let mut service = sessions.lock().unwrap();
    let binding = service.current_binding().clone();
    let challenge = service
        .issue_challenge([41; 32], [42; 32], Duration::ZERO)
        .unwrap();
    let mut mac = HmacSha256::new_from_slice(&[16; 32]).unwrap();
    mac.update(&bootstrap_proof_transcript(&binding, [42; 32], [41; 32]));
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            [43; 32],
            Duration::ZERO,
        )
        .unwrap();
    binding
}

#[test]
fn v3_ticket_uses_the_shared_boot_clock_when_session_clock_differs() {
    let (owned, keys, sessions) = owned_and_sessions();
    let (mut client, server) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        run_control_loop_v3(
            ProtectedActivationChannel::new(server).unwrap(),
            keys,
            owned,
            sessions,
            Arc::new(|| Duration::from_secs(7)),
            Arc::new(|| Ok(50_000)),
            super::super::enrollment_control_transition::DaemonEnrollmentRendezvous::for_test(),
        )
    });
    let (owned, keys, _) = owned_and_sessions();
    let mut renewal = ProtectedCredentialEnrollmentRenewRequestV3::new(owned, 1, [31; 32]).unwrap();
    renewal.sign(&keys);
    client.write_all(&renewal.encode_frame().unwrap()).unwrap();
    let ticket =
        ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(&read_frame(&mut client)).unwrap();
    assert_eq!(ticket.issued_at_monotonic_millis(), 50_000);
    assert_eq!(ticket.expires_at_monotonic_millis(), 80_000);
    let next = ticket
        .verify_exact_at(&renewal, 50_000, &keys)
        .unwrap()
        .next_owned_launch();
    assert!(ticket.verify_exact_at(&renewal, 7_000, &keys).is_err());
    assert!(ticket.verify_exact_at(&renewal, 80_000, &keys).is_ok());
    let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(next.clone());
    shutdown.sign(&keys);
    client.write_all(&shutdown.encode_frame().unwrap()).unwrap();
    let acknowledgement =
        ProtectedCredentialEnrollmentShutdownAckV3::decode_frame(&read_frame(&mut client)).unwrap();
    acknowledgement.verify_exact(&next, &keys).unwrap();
    server.join().unwrap().unwrap();
}

#[test]
fn v3_ticket_clock_rejects_expiry_overflow() {
    let (owned, keys, sessions) = owned_and_sessions();
    let observed_sessions = Arc::clone(&sessions);
    let expected_binding = sessions.lock().unwrap().current_binding().clone();
    let (mut client, server) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        run_control_loop_v3(
            ProtectedActivationChannel::new(server).unwrap(),
            keys,
            owned,
            sessions,
            Arc::new(|| Duration::ZERO),
            Arc::new(|| Ok(u64::MAX - 29_999)),
            super::super::enrollment_control_transition::DaemonEnrollmentRendezvous::for_test(),
        )
    });
    let (owned, keys, _) = owned_and_sessions();
    let mut renewal = ProtectedCredentialEnrollmentRenewRequestV3::new(owned, 1, [32; 32]).unwrap();
    renewal.sign(&keys);
    client.write_all(&renewal.encode_frame().unwrap()).unwrap();
    // The ticket-clock failure itself terminates the loop; dropping the peer
    // here would race the server thread's loop entry with an unrelated error.
    assert_eq!(
        server.join().unwrap(),
        Err(runne_api::LaunchAuthorityError::RenewalUnavailable)
    );
    let mut service = observed_sessions.lock().unwrap();
    assert_eq!(service.current_binding(), &expected_binding);
    assert!(
        service
            .issue_challenge([44; 32], [45; 32], Duration::ZERO)
            .is_ok()
    );
}

#[test]
fn v3_ticket_clock_error_leaves_the_existing_session_unrevoked() {
    let (owned, keys, sessions) = owned_and_sessions();
    let expected_binding = authenticate_existing_session(&sessions);
    let observed_sessions = Arc::clone(&sessions);
    let (mut client, server) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        run_control_loop_v3(
            ProtectedActivationChannel::new(server).unwrap(),
            keys,
            owned,
            sessions,
            Arc::new(|| Duration::ZERO),
            Arc::new(|| Err(runne_api::LaunchAuthorityError::RenewalUnavailable)),
            super::super::enrollment_control_transition::DaemonEnrollmentRendezvous::for_test(),
        )
    });
    let (owned, keys, _) = owned_and_sessions();
    let mut renewal = ProtectedCredentialEnrollmentRenewRequestV3::new(owned, 1, [46; 32]).unwrap();
    renewal.sign(&keys);
    client.write_all(&renewal.encode_frame().unwrap()).unwrap();
    // The ticket-clock failure itself terminates the loop; dropping the peer
    // here would race the server thread's loop entry with an unrelated error.
    assert_eq!(
        server.join().unwrap(),
        Err(runne_api::LaunchAuthorityError::RenewalUnavailable)
    );
    let mut service = observed_sessions.lock().unwrap();
    assert_eq!(service.current_binding(), &expected_binding);
    assert!(service.authorize_wire(&[43; 32], Duration::ZERO).is_ok());
}

#[test]
fn v3_ticket_write_failure_terminates_the_control_loop() {
    let (owned, keys, sessions) = owned_and_sessions();
    let observed_sessions = Arc::clone(&sessions);
    let initial_binding = sessions.lock().unwrap().current_binding().clone();
    let (mut client, server) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        run_control_loop_v3(
            ProtectedActivationChannel::new(server).unwrap(),
            keys,
            owned,
            sessions,
            Arc::new(|| Duration::ZERO),
            Arc::new(|| Ok(1_000)),
            super::super::enrollment_control_transition::DaemonEnrollmentRendezvous::for_test(),
        )
    });
    let (owned, keys, _) = owned_and_sessions();
    let mut renewal = ProtectedCredentialEnrollmentRenewRequestV3::new(owned, 1, [47; 32]).unwrap();
    renewal.sign(&keys);
    client.write_all(&renewal.encode_frame().unwrap()).unwrap();
    // Wait for the observed rotation before closing the peer: the ticket write
    // then fails against a vanished (or draining) peer after the rotation, not
    // the loop entry racing a lost socketpair end.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while observed_sessions.lock().unwrap().current_binding() == &initial_binding {
        assert!(
            std::time::Instant::now() < deadline,
            "daemon never rotated the session"
        );
        std::thread::yield_now();
    }
    drop(client);
    assert_eq!(
        server.join().unwrap(),
        Err(runne_api::LaunchAuthorityError::ProtectedChannelUnavailable)
    );
    assert_ne!(
        observed_sessions.lock().unwrap().current_binding(),
        &initial_binding
    );
}
