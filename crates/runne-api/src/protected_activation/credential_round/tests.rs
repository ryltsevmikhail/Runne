use super::*;
use crate::protected_activation::enrollment_launch_v3_tests::{fixture, id};

fn peers() -> (ProtectedCredentialRoundCodec, ProtectedCredentialRoundCodec) {
    let (_, ready, keys) = fixture();
    (
        ProtectedCredentialRoundCodec::new(&keys, &ready.owned_launch()),
        ProtectedCredentialRoundCodec::new(&keys, &ready.owned_launch()),
    )
}

#[test]
fn credential_round_authenticates_fresh_broker_and_ack_without_replay() {
    let (mut desktop, mut daemon) = peers();
    let request = desktop.encode_request([31; 32]).unwrap();
    daemon.decode_request(&request).unwrap();
    assert!(daemon.decode_request(&request).is_err());
    let facts = ProtectedCredentialRoundBrokerFacts::new([32; 32], [33; 32]).unwrap();
    let offer = daemon.encode_offer(facts).unwrap();
    let received = desktop.decode_offer(&offer).unwrap();
    assert_eq!(received.channel_binding(), [32; 32]);
    assert_eq!(received.publication_key(), [33; 32]);
    assert!(desktop.decode_offer(&offer).is_err());
    let ack = desktop.encode_accept().unwrap();
    daemon.decode_accept(&ack).unwrap();
    assert!(daemon.decode_accept(&ack).is_err());
    assert!(desktop.encode_request([34; 32]).is_err());
    assert!(desktop.encode_accept().is_err());
}

#[test]
fn credential_round_rejects_other_owned_session_and_tampered_request() {
    let (mut desktop, mut daemon) = peers();
    let request = desktop.encode_request([31; 32]).unwrap();
    let (_, ready, keys) = fixture();
    for field in 0..8 {
        let mut other = ready.owned_launch();
        match field {
            0 => other.core.session_id = id(42),
            1 => other.core.daemon_id = id(42),
            2 => other.core.generation += 1,
            3 => other.enrollment.release_tuple_digest = [42; 32],
            4 => other.enrollment.qualification_binding_digest = [42; 32],
            5 => other.enrollment.desktop_peer_binding_digest = [42; 32],
            6 => other.enrollment.installation_identity_digest = [42; 32],
            _ => other.enrollment.desktop_supervisor_generation += 1,
        }
        let mut other = ProtectedCredentialRoundCodec::new(&keys, &other);
        assert!(other.decode_request(&request).is_err());
    }
    for index in 0..request.len() {
        let mut bad = request.clone();
        bad[index] ^= 1;
        assert!(daemon.decode_request(&bad).is_err());
    }
    daemon.decode_request(&request).unwrap();
}

#[test]
fn credential_round_accept_cannot_ack_another_broker_offer() {
    let (mut desktop, mut daemon) = peers();
    let (_, mut other_daemon) = peers();
    let request = desktop.encode_request([31; 32]).unwrap();
    daemon.decode_request(&request).unwrap();
    other_daemon.decode_request(&request).unwrap();
    let offer = daemon
        .encode_offer(ProtectedCredentialRoundBrokerFacts::new([32; 32], [33; 32]).unwrap())
        .unwrap();
    other_daemon
        .encode_offer(ProtectedCredentialRoundBrokerFacts::new([34; 32], [33; 32]).unwrap())
        .unwrap();
    desktop.decode_offer(&offer).unwrap();
    let ack = desktop.encode_accept().unwrap();
    assert!(other_daemon.decode_accept(&ack).is_err());
    daemon.decode_accept(&ack).unwrap();
}

#[test]
fn credential_round_requires_order_and_nonzero_entropy() {
    let (mut desktop, mut daemon) = peers();
    assert!(desktop.encode_request([0; 32]).is_err());
    assert!(ProtectedCredentialRoundBrokerFacts::new([0; 32], [33; 32]).is_err());
    assert!(ProtectedCredentialRoundBrokerFacts::new([32; 32], [0; 32]).is_err());
    assert!(
        daemon
            .encode_offer(ProtectedCredentialRoundBrokerFacts::new([32; 32], [33; 32]).unwrap())
            .is_err()
    );
    assert!(desktop.encode_accept().is_err());
    assert!(daemon.decode_accept(&[]).is_err());
    assert!(desktop.encode_request([31; 32]).is_ok());
}

#[test]
fn credential_round_rejects_authenticated_wrong_version_kind_and_zero_nonce() {
    let (mut desktop, mut daemon) = peers();
    let request = desktop.encode_request([31; 32]).unwrap();
    for position in [12, 13, 14, 46] {
        let mut bad = request.clone();
        if position == 46 {
            bad[46..78].fill(0);
        } else {
            bad[position] ^= 1;
        }
        let end = bad.len() - 32;
        let proof = authenticated_mac(&desktop.key, DOMAIN, &bad[4..end]);
        bad[end..].copy_from_slice(&proof);
        assert!(daemon.decode_request(&bad).is_err());
    }
    for end in 0..request.len() {
        assert!(daemon.decode_request(&request[..end]).is_err());
    }
    let mut trailing = request.clone();
    trailing.push(0);
    assert!(daemon.decode_request(&trailing).is_err());
    daemon.decode_request(&request).unwrap();
}

#[test]
fn credential_round_offer_rejects_other_request_nonce_without_advancing() {
    let (mut desktop, mut daemon) = peers();
    let (mut other_desktop, mut other_daemon) = peers();
    daemon
        .decode_request(&desktop.encode_request([31; 32]).unwrap())
        .unwrap();
    other_daemon
        .decode_request(&other_desktop.encode_request([41; 32]).unwrap())
        .unwrap();
    let facts = ProtectedCredentialRoundBrokerFacts::new([32; 32], [33; 32]).unwrap();
    let other = other_daemon.encode_offer(facts).unwrap();
    assert!(desktop.decode_offer(&other).is_err());
    let valid = daemon.encode_offer(facts).unwrap();
    for position in 0..valid.len() {
        let mut bad = valid.clone();
        bad[position] ^= 1;
        assert!(desktop.decode_offer(&bad).is_err());
    }
    desktop.decode_offer(&valid).unwrap();
}
