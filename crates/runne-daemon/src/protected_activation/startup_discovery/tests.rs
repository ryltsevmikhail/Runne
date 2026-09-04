use super::*;
use crate::protected_activation::enrollment_control_transition_fixture::v2_launch;

fn service(owned: &ProtectedOwnedLaunchV2, stale: bool) -> Mutex<LocalSessionService> {
    let stable = owned.compatibility_owned_launch().stable();
    let binding = RuntimeSessionBinding::new(
        runne_api::StableRuntimeBinding::new(
            *stable.authority_id(),
            runne_api::ApiPrincipalId::new(stable.principal_id()).unwrap(),
            runne_api::EventLogLineageId::from_bytes(*stable.lineage_id()),
            stable.profile_id(),
            *stable.profile_hash(),
            *stable.capability_digest(),
        )
        .unwrap(),
        runne_api::DaemonInstanceId::from_bytes(*owned.daemon_instance_id()),
        owned.launch_generation(),
        if stale { [77; 16] } else { *owned.session_id() },
        1,
        runne_domain::event::Sensitivity::Public,
        [14; 32],
    )
    .unwrap();
    Mutex::new(
        LocalSessionService::new_protected(
            binding,
            [1; 32],
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap(),
    )
}

#[test]
fn startup_discovery_holds_exact_session_lock_through_read_only_query() {
    let (_, owned, _, _) = v2_launch();
    let sessions = service(&owned, false);
    let before = sessions.lock().unwrap().current_binding().clone();
    assert_eq!(
        with_current(&sessions, &owned, || {
            assert!(matches!(
                sessions.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            Ok(vec![[7; 16]])
        })
        .unwrap(),
        vec![[7; 16]]
    );
    assert_eq!(sessions.lock().unwrap().current_binding(), &before);
    let stale = service(&owned, true);
    let mut queried = false;
    assert!(
        with_current(&stale, &owned, || {
            queried = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!queried);
}

#[test]
fn startup_discovery_without_verified_installation_returns_no_metadata() {
    use std::os::unix::net::UnixStream;
    let (_, owned, keys, _) = v2_launch();
    let sessions = service(&owned, false);
    let before = sessions.lock().unwrap().current_binding().clone();
    let request = runne_api::ProtectedCredentialDiscoveryCodec::for_startup(&keys, &owned)
        .encode_request([19; 32])
        .unwrap();
    let (mut peer, stream) = UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    let mut channel = ProtectedActivationChannel::new(stream).unwrap();
    assert_eq!(
        respond(&mut channel, &keys, &owned, &sessions, None, &request),
        Err(LaunchAuthorityError::OwnershipMismatch)
    );
    assert_eq!(
        peer.read(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(sessions.lock().unwrap().current_binding(), &before);
}
