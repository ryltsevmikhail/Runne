use super::*;
use crate::protected_runtime::{
    credential_discovery::{prepare, reap},
    read_frame, test_only_ready_v3_enrollment_supervisor, write_frame,
};
use runne_api::{
    CredentialServiceRejoinBinding, CredentialServiceSessionAuthenticator,
    ProtectedCredentialEnrollmentLifecycleCodec as Codec,
    ProviderCredentialOperationSnapshotV2 as Snapshot, ProviderCredentialOperationStateV2 as State,
};
use std::{os::unix::net::UnixStream, time::Duration};

fn snapshot(state: State, pair: bool) -> Snapshot {
    Snapshot::new(
        runne_api::ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
        None,
        runne_api::ProviderCredentialProviderV2::OpenAi,
        if pair {
            runne_api::ProviderCredentialOperationKindV2::Pair
        } else {
            runne_api::ProviderCredentialOperationKindV2::Revoke
        },
        state,
        1,
        1,
        false,
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn pair_terminal_rejoins_after_exactly_one_relay_ack() {
    terminal_rejoin(true).await;
}

#[tokio::test]
async fn revoke_terminal_rejoins_without_pair_ack() {
    terminal_rejoin(false).await;
}

async fn terminal_rejoin(pair: bool) {
    for tamper in [false, true] {
        let fixture = test_only_ready_v3_enrollment_supervisor();
        let owned = fixture.owned_launch().unwrap();
        let (desktop, mut peer) = UnixStream::pair().unwrap();
        desktop
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (supervisor, registration) = prepare(fixture, desktop, tamper).unwrap();
        let keys = runne_api::LaunchSecret::from_bytes([3; 32])
            .unwrap()
            .derive_keys();
        let enrollment = PreparedProtectedCredentialEnrollment {
            codec: Codec::from_protected_activation(&keys),
            snapshot: snapshot(State::Prepared, pair),
            relay: pair.then_some([7; 388]),
            relay_taken: pair,
            terminal: false,
        };
        let daemon = std::thread::spawn(move || {
            let codec = Codec::from_protected_activation(&keys);
            if pair {
                let ack = read_frame(&mut peer).unwrap();
                codec.decode_desktop_relay_ack(&ack, 1, &[7; 388]).unwrap();
            }
            let binding = owned.enrollment_binding();
            let now = crate::protected_runtime::credential_service_session::unix_millis().unwrap();
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
                now + 5_000,
            )
            .unwrap();
            let auth = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
            write_frame(&mut peer, &auth.require_rejoin(rejoin).into_control_frame()).unwrap();
            let Ok(claim) = read_frame(&mut peer) else {
                return false;
            };
            let Ok(ack) = read_frame(&mut peer) else {
                return false;
            };
            let verified = auth.decode_and_verify_registration(&claim[4..]).unwrap();
            auth.decode_and_verify_ack_for(&ack[4..], verified.binding(), now)
                .unwrap();
            write_frame(
                &mut peer,
                &codec
                    .encode_daemon_snapshot(
                        &snapshot(State::Completed, pair),
                        if pair { 3 } else { 2 },
                    )
                    .unwrap(),
            )
            .unwrap();
            true
        });
        let result = if pair {
            finish(Arc::clone(&supervisor), enrollment, &[7; 388], registration).await
        } else {
            control_only::receive(Arc::clone(&supervisor), enrollment, registration).await
        };
        reap(&supervisor);
        let sent = daemon.join().unwrap();
        if tamper {
            assert!(result.is_err());
            assert!(!sent);
        } else {
            let completed = result.unwrap();
            assert!(completed.terminal());
            assert_eq!(completed.snapshot(), &snapshot(State::Completed, pair));
            assert!(sent);
        }
    }
}
