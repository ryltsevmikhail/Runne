use super::*;
use crate::protected_runtime::{
    credential_discovery::{prepare, reap},
    read_frame, test_only_ready_v3_enrollment_supervisor, write_frame,
};
use runne_api::{
    CredentialServiceRejoinBinding, CredentialServiceSessionAuthenticator,
    ProtectedCredentialEnrollmentShutdownAckV3, ProtectedCredentialEnrollmentShutdownV3,
};
use std::{os::unix::net::UnixStream, time::Duration};

#[tokio::test]
async fn shutdown_services_one_rejoin_before_accepting_graceful_ack() {
    for (tamper, graceful, corrupt_shutdown) in [
        (false, true, false),
        (true, true, false),
        (false, false, false),
        (false, true, true),
    ] {
        let fixture = test_only_ready_v3_enrollment_supervisor();
        let owned = fixture.owned_launch().unwrap();
        let expected = owned.clone();
        let (desktop, mut peer) = UnixStream::pair().unwrap();
        desktop
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (supervisor, registration) = prepare(fixture, desktop, tamper).unwrap();
        let daemon = std::thread::spawn(move || {
            let keys = runne_api::LaunchSecret::from_bytes([3; 32])
                .unwrap()
                .derive_keys();
            let enrollment = owned.enrollment_binding();
            let now = crate::protected_runtime::credential_service_session::unix_millis().unwrap();
            let binding = CredentialServiceRejoinBinding::new(
                [9; 16],
                *owned.session_id(),
                owned.launch_generation(),
                owned.launch_generation(),
                enrollment.desktop_supervisor_generation(),
                1,
                *enrollment.installation_identity_digest(),
                *enrollment.release_tuple_digest(),
                2,
                now + 5_000,
            )
            .unwrap();
            let auth = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
            write_frame(
                &mut peer,
                &auth.require_rejoin(binding).into_control_frame(),
            )
            .unwrap();
            ProtectedCredentialEnrollmentShutdownV3::decode_frame(&read_frame(&mut peer).unwrap())
                .unwrap()
                .verify_exact(&owned, &keys)
                .unwrap();
            let Ok(claim) = read_frame(&mut peer) else {
                return false;
            };
            let Ok(ack) = read_frame(&mut peer) else {
                return false;
            };
            let verified = auth.decode_and_verify_registration(&claim[4..]).unwrap();
            auth.decode_and_verify_ack_for(&ack[4..], verified.binding(), now)
                .unwrap();
            let mut ack = ProtectedCredentialEnrollmentShutdownAckV3::new(owned, graceful);
            ack.sign(&keys);
            let mut frame = ack.encode_frame().unwrap();
            if corrupt_shutdown {
                *frame.last_mut().unwrap() ^= 1;
            }
            write_frame(&mut peer, &frame).unwrap();
            true
        });
        let result = request(Arc::clone(&supervisor), expected, registration).await;
        let acknowledged = supervisor
            .lock()
            .unwrap()
            .process
            .as_ref()
            .unwrap()
            .graceful_acknowledged;
        reap(&supervisor);
        let sent = daemon.join().unwrap();
        if tamper {
            assert!(result.is_err());
            assert!(!acknowledged && !sent);
        } else if !graceful || corrupt_shutdown {
            assert!(result.is_err());
            assert!(!acknowledged && sent);
        } else {
            result.unwrap();
            assert!(acknowledged && sent);
        }
    }
}
