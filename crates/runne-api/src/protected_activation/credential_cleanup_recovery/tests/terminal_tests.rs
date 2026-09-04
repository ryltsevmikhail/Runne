use super::*;
use crate::{
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2,
};

fn terminal() -> ProviderCredentialOperationSnapshotV2 {
    ProviderCredentialOperationSnapshotV2::new(
        ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
        None,
        ProviderCredentialProviderV2::OpenAi,
        ProviderCredentialOperationKindV2::Revoke,
        ProviderCredentialOperationStateV2::Completed,
        3,
        3,
        false,
        None,
    )
    .unwrap()
}

fn accepted(
    expected: &ProtectedCredentialRecoveryOffer,
) -> (
    ProtectedCredentialRecoveryCodec,
    ProtectedCredentialRecoveryCodec,
) {
    let (mut daemon, mut desktop) = (codec(), codec());
    let frame = daemon.encode_daemon_offer(expected, 100).unwrap();
    let received = desktop.decode_daemon_offer(&frame, 100).unwrap();
    let ack = desktop.encode_desktop_accept(&received, 100).unwrap();
    daemon.decode_desktop_accept(&ack, expected, 100).unwrap();
    (daemon, desktop)
}

#[test]
fn recovery_terminal_closes_offer_and_accept_in_both_directions() {
    let expected = offer();
    let (mut daemon, mut desktop) = accepted(&expected);
    // Authenticated frames at the next valid sequence must still be rejected
    // after terminal; the failure must not depend on a stale sequence or MAC.
    let mut later_offer_sender = codec();
    later_offer_sender.sent = 2;
    let later_offer = later_offer_sender
        .encode_daemon_offer(&expected, 101)
        .unwrap();
    let mut later_accept_sender = codec();
    later_accept_sender.sent = 1;
    let later_accept = later_accept_sender
        .encode_desktop_accept(&expected, 101)
        .unwrap();
    let terminal_frame = daemon.encode_daemon_terminal(&terminal()).unwrap();
    desktop.decode_daemon_terminal(&terminal_frame).unwrap();

    assert!(daemon.encode_daemon_offer(&expected, 101).is_err());
    assert!(desktop.encode_desktop_accept(&expected, 101).is_err());
    assert!(desktop.decode_daemon_offer(&later_offer, 101).is_err());
    assert!(
        daemon
            .decode_desktop_accept(&later_accept, &expected, 101)
            .is_err()
    );
}

#[test]
fn recovery_terminal_requires_accept_and_binds_exact_attempt() {
    assert!(codec().encode_daemon_terminal(&terminal()).is_err());
    let (mut daemon, mut desktop) = accepted(&offer());
    let frame = daemon.encode_daemon_terminal(&terminal()).unwrap();
    let mut other = offer();
    other.attempt = 2;
    let (_, mut other_desktop) = accepted(&other);
    assert!(other_desktop.decode_daemon_terminal(&frame).is_err());
    assert_eq!(desktop.decode_daemon_terminal(&frame).unwrap(), terminal());
    assert!(desktop.decode_daemon_terminal(&frame).is_err());
    assert!(daemon.encode_daemon_terminal(&terminal()).is_err());
}

#[test]
fn recovery_terminal_rejects_tampering_without_consuming_valid_result() {
    let (mut daemon, mut desktop) = accepted(&offer());
    let frame = daemon.encode_daemon_terminal(&terminal()).unwrap();
    for index in 0..frame.len() {
        let mut bad = frame.clone();
        bad[index] ^= 1;
        assert!(desktop.decode_daemon_terminal(&bad).is_err());
    }
    assert_eq!(desktop.decode_daemon_terminal(&frame).unwrap(), terminal());
}

#[test]
fn recovery_terminal_rejects_authenticated_nonterminal_and_noncanonical_payloads() {
    let prepared = ProviderCredentialOperationSnapshotV2::new(
        ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap(),
        None,
        ProviderCredentialProviderV2::OpenAi,
        ProviderCredentialOperationKindV2::Revoke,
        ProviderCredentialOperationStateV2::Prepared,
        3,
        3,
        false,
        None,
    )
    .unwrap();
    for nonterminal in [true, false] {
        let (mut daemon, mut desktop) = accepted(&offer());
        assert!(daemon.encode_daemon_terminal(&prepared).is_err());
        let mut payload = daemon.accepted_offer.unwrap().to_vec();
        if !nonterminal {
            payload.push(b' ');
        }
        let completed = terminal();
        payload
            .extend(serde_json::to_vec(if nonterminal { &prepared } else { &completed }).unwrap());
        let frame = daemon.encode(4, &payload).unwrap();
        assert!(desktop.decode_daemon_terminal(&frame).is_err());
        assert_eq!(desktop.received, 1);
    }
}
