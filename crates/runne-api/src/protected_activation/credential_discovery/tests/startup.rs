use super::*;
use crate::protected_activation::{ProtectedOwnedLaunchV1, ProtectedOwnedLaunchV2};

fn owned() -> (
    ProtectedOwnedLaunchV2,
    ProtectedCredentialEnrollmentOwnedLaunchV3,
    ProtectedActivationKeys,
) {
    let (launch, ready, keys) = fixture();
    let v1 = ProtectedOwnedLaunchV1::new(
        launch.launch_authority_id(),
        launch.desktop_host_instance_id(),
        ready.executable().clone(),
        ready.profile().clone(),
        ready.stable().clone(),
        *ready.daemon_instance_id(),
        ready.launch_generation(),
        *ready.session_id(),
    )
    .unwrap();
    (
        ProtectedOwnedLaunchV2::new(v1, launch.provider_binding().clone()).unwrap(),
        ready.owned_launch(),
        keys,
    )
}

#[test]
fn startup_discovery_reads_empty_or_pending_without_v3_authority() {
    let (v2, _, keys) = owned();
    for ids in [vec![], vec![[7; 16]]] {
        let mut desktop = ProtectedCredentialDiscoveryCodec::for_startup(&keys, &v2);
        let mut daemon = ProtectedCredentialDiscoveryCodec::for_startup(&keys, &v2);
        let request = desktop.encode_request([19; 32]).unwrap();
        daemon.decode_request(&request).unwrap();
        let response = daemon.encode_response(&ids).unwrap();
        assert_eq!(desktop.decode_response(&response).unwrap(), ids);
        assert!(desktop.decode_response(&response).is_err());
    }
}

#[test]
fn startup_discovery_never_crosses_v2_v3_contexts_even_with_same_launch_keys() {
    let (v2, v3, keys) = owned();
    let request = ProtectedCredentialDiscoveryCodec::for_startup(&keys, &v2)
        .encode_request([19; 32])
        .unwrap();
    assert!(
        ProtectedCredentialDiscoveryCodec::new(&keys, &v3)
            .decode_request(&request)
            .is_err()
    );
    let request = ProtectedCredentialDiscoveryCodec::new(&keys, &v3)
        .encode_request([19; 32])
        .unwrap();
    assert!(
        ProtectedCredentialDiscoveryCodec::for_startup(&keys, &v2)
            .decode_request(&request)
            .is_err()
    );
}

#[test]
fn startup_discovery_rejects_changes_to_bound_v2_identity() {
    let (v2, _, keys) = owned();
    let request = ProtectedCredentialDiscoveryCodec::for_startup(&keys, &v2)
        .encode_request([19; 32])
        .unwrap();
    for field in 0..5 {
        let mut other = v2.clone();
        let core = &mut other.compatibility_owned_launch;
        match field {
            0 => core.session_id = [55; 16],
            1 => core.daemon_instance_id = [55; 16],
            2 => core.launch_generation += 1,
            3 => core.launch_authority_id = [55; 16],
            _ => core.desktop_host_instance_id = [55; 16],
        }
        assert!(
            ProtectedCredentialDiscoveryCodec::for_startup(&keys, &other)
                .decode_request(&request)
                .is_err()
        );
    }
    let other_keys = crate::LaunchSecret::from_bytes([99; 32])
        .unwrap()
        .derive_keys();
    assert!(
        ProtectedCredentialDiscoveryCodec::for_startup(&other_keys, &v2)
            .decode_request(&request)
            .is_err()
    );
}
