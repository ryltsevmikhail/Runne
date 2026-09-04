use super::*;
use crate::protected_activation::enrollment_launch_v3_tests::fixture;
mod startup;

fn peers() -> (
    ProtectedCredentialDiscoveryCodec,
    ProtectedCredentialDiscoveryCodec,
) {
    let (_, ready, keys) = fixture();
    (
        ProtectedCredentialDiscoveryCodec::new(&keys, &ready.owned_launch()),
        ProtectedCredentialDiscoveryCodec::new(&keys, &ready.owned_launch()),
    )
}

#[test]
fn discovery_roundtrip_accepts_empty_or_bounded_metadata_once() {
    for ids in [vec![], vec![[7; 16]], (1..=64).map(|n| [n; 16]).collect()] {
        let (mut desktop, mut daemon) = peers();
        let request = desktop.encode_request([19; 32]).unwrap();
        daemon.decode_request(&request).unwrap();
        assert!(daemon.decode_request(&request).is_err());
        let response = daemon.encode_response(&ids).unwrap();
        assert_eq!(desktop.decode_response(&response).unwrap(), ids);
        assert!(desktop.decode_response(&response).is_err());
        assert!(daemon.encode_response(&ids).is_err());
    }
}

#[test]
fn discovery_rejects_invalid_ids_and_bounds_without_consuming_response() {
    let (mut desktop, mut daemon) = peers();
    assert!(desktop.encode_request([0; 32]).is_err());
    assert!(daemon.encode_response(&[]).is_err());
    daemon
        .decode_request(&desktop.encode_request([19; 32]).unwrap())
        .unwrap();
    for ids in [
        vec![[0; 16]],
        vec![[7; 16]; 2],
        (1..=65).map(|n| [n; 16]).collect(),
    ] {
        assert!(daemon.encode_response(&ids).is_err());
    }
    assert_eq!(
        desktop
            .decode_response(&daemon.encode_response(&[[7; 16]]).unwrap())
            .unwrap(),
        vec![[7; 16]]
    );
}

#[test]
fn discovery_rejects_other_session_nonce_and_corruption_without_advancing() {
    let (mut desktop, mut daemon) = peers();
    let request = desktop.encode_request([19; 32]).unwrap();
    let (_, ready, keys) = fixture();
    let mut owned = ready.owned_launch();
    owned.core.session_id = [55; 16];
    assert!(
        ProtectedCredentialDiscoveryCodec::new(&keys, &owned)
            .decode_request(&request)
            .is_err()
    );
    for pos in 0..request.len() {
        let mut bad = request.clone();
        bad[pos] ^= 1;
        assert!(daemon.decode_request(&bad).is_err());
    }
    daemon.decode_request(&request).unwrap();
    let response = daemon.encode_response(&[[7; 16]]).unwrap();
    let (mut other, mut other_daemon) = peers();
    other_daemon
        .decode_request(&other.encode_request([20; 32]).unwrap())
        .unwrap();
    assert!(
        desktop
            .decode_response(&other_daemon.encode_response(&[[7; 16]]).unwrap())
            .is_err()
    );
    for pos in 0..response.len() {
        let mut bad = response.clone();
        bad[pos] ^= 1;
        assert!(desktop.decode_response(&bad).is_err());
    }
    for end in 0..response.len() {
        assert!(desktop.decode_response(&response[..end]).is_err());
    }
    let mut trailing = response.clone();
    trailing.push(0);
    assert!(desktop.decode_response(&trailing).is_err());
    assert_eq!(desktop.decode_response(&response).unwrap(), vec![[7; 16]]);
}

#[test]
fn discovery_rejects_authenticated_malformed_response_payload() {
    let (mut desktop, mut daemon) = peers();
    daemon
        .decode_request(&desktop.encode_request([19; 32]).unwrap())
        .unwrap();
    for ids in [
        vec![[0; 16]],
        vec![[7; 16]; 2],
        (1..=65).map(|n| [n; 16]).collect(),
    ] {
        let mut payload = vec![19; 32];
        payload.push(ids.len() as u8);
        for id in ids {
            payload.extend_from_slice(&id);
        }
        let frame = daemon.encode(2, &payload);
        assert!(desktop.decode_response(&frame).is_err());
    }
    let mut wrong_count = vec![19; 32];
    wrong_count.push(1);
    assert!(
        desktop
            .decode_response(&daemon.encode(2, &wrong_count))
            .is_err()
    );
    assert!(
        desktop
            .decode_response(&daemon.encode(3, &[19; 33]))
            .is_err()
    );
    assert!(
        desktop
            .decode_response(&daemon.encode_response(&[]).unwrap())
            .unwrap()
            .is_empty()
    );
}
