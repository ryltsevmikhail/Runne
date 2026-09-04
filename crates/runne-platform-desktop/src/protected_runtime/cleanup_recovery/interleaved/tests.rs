use super::super::{ProtectedCredentialRecoveryCodec, now_seconds, write_frame};
use super::*;
use crate::protected_runtime::{
    credential_discovery::{prepare, reap},
    test_only_ready_v3_enrollment_supervisor,
};
use runne_api::{
    CredentialServiceRejoinBinding, CredentialServiceSessionAuthenticator,
    ProtectedCredentialRecoveryContext, ProtectedCredentialRecoveryOffer,
};
use sha2::{Digest, Sha256};
use std::{os::unix::net::UnixStream, time::Duration};

#[tokio::test]
async fn terminal_validation_rejects_stopping_or_changed_bootstrap() {
    let fixture = test_only_ready_v3_enrollment_supervisor();
    let (channel, _peer) = UnixStream::pair().unwrap();
    let (supervisor, _) = prepare(fixture, channel, false).unwrap();
    let (stopping, changed) = {
        let mut guard = supervisor.lock().unwrap();
        let current = guard
            .recovery_process()
            .unwrap()
            .recovery_bootstrap()
            .unwrap();
        guard.process.as_mut().unwrap().graceful_requested = true;
        let stopping = validate(&mut guard, &current).is_err();
        guard.process.as_mut().unwrap().graceful_requested = false;
        let foreign = ProtectedCredentialRecoveryBootstrap::new(
            [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], 9,
        )
        .unwrap();
        let changed = validate(&mut guard, &foreign).is_err();
        drop(guard);
        (stopping, changed)
    };
    reap(&supervisor);
    assert!(stopping && changed);
}

#[tokio::test]
async fn recovery_terminal_services_rejoin_without_repeating_recovery_request() {
    for tamper in [false, true] {
        let fixture = test_only_ready_v3_enrollment_supervisor();
        let owned = fixture.owned_launch().unwrap();
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
            let binding = owned.enrollment_binding();
            let context = recovery_context(&owned);
            let mut codec = ProtectedCredentialRecoveryCodec::new(&keys, context.clone());
            let operation = codec
                .decode_desktop_request(&read_frame(&mut peer).unwrap())
                .unwrap();
            assert_eq!(operation, [9; 16]);
            let now = now_seconds().unwrap();
            let offer = ProtectedCredentialRecoveryOffer::new(
                context,
                operation,
                [10; 32],
                1,
                2,
                3,
                now,
                now + 30,
            )
            .unwrap();
            write_frame(&mut peer, &codec.encode_daemon_offer(&offer, now).unwrap()).unwrap();
            codec
                .decode_desktop_accept(&read_frame(&mut peer).unwrap(), &offer, now)
                .unwrap();
            let expiry = crate::protected_runtime::credential_service_session::unix_millis()
                .unwrap()
                + 5_000;
            let rejoin = CredentialServiceRejoinBinding::new(
                [9; 16],
                *owned.session_id(),
                owned.launch_generation(),
                owned.launch_generation(),
                binding.desktop_supervisor_generation(),
                1,
                *binding.installation_identity_digest(),
                *binding.release_tuple_digest(),
                2,
                expiry,
            )
            .unwrap();
            write_frame(
                &mut peer,
                &CredentialServiceSessionAuthenticator::from_protected_activation(&keys)
                    .require_rejoin(rejoin)
                    .into_control_frame(),
            )
            .unwrap();
            let Ok(claim) = read_frame(&mut peer) else {
                return false;
            };
            let Ok(ack) = read_frame(&mut peer) else {
                return false;
            };
            let auth = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
            let verified = auth.decode_and_verify_registration(&claim[4..]).unwrap();
            auth.decode_and_verify_ack_for(&ack[4..], verified.binding(), expiry - 4_000)
                .unwrap();
            write_frame(
                &mut peer,
                &codec
                    .encode_daemon_terminal(&super::super::tests::terminal())
                    .unwrap(),
            )
            .unwrap();
            true
        });
        let recovery = supervisor
            .lock()
            .unwrap()
            .begin_protected_credential_recovery([9; 16])
            .unwrap();
        let result = finish(Arc::clone(&supervisor), recovery, registration).await;
        reap(&supervisor);
        let sent = daemon.join().unwrap();
        if tamper {
            assert!(result.is_err());
            assert!(!sent);
        } else {
            assert_eq!(result.unwrap(), super::super::tests::terminal());
            assert!(sent);
        }
    }
}

fn recovery_context(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> ProtectedCredentialRecoveryContext {
    let binding = owned.enrollment_binding();
    let mut hash = Sha256::new();
    hash.update(b"gocode/provider-credential-enrollment/session/v1\0");
    for part in [
        owned.launch_authority_id().as_slice(),
        owned.session_id().as_slice(),
        owned.daemon_instance_id().as_slice(),
        &owned.launch_generation().to_be_bytes(),
    ] {
        hash.update(u32::try_from(part.len()).unwrap().to_be_bytes());
        hash.update(part);
    }
    ProtectedCredentialRecoveryContext::new(
        *binding.installation_identity_digest(),
        *binding.release_tuple_digest(),
        hash.finalize().into(),
        [4; 32],
        *binding.desktop_peer_binding_digest(),
        runne_api::protected_credential_broker_evidence_binding(
            *binding.release_tuple_digest(),
            [31; 32],
            [32; 32],
        ),
        7,
        binding.desktop_supervisor_generation(),
    )
    .unwrap()
}
