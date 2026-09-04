#[cfg(feature = "test-support")]
use super::super::{
    test_only_absent_enrollment_supervisor, test_only_ready_v3_enrollment_supervisor,
};
use super::*;
use runne_api::LaunchSecret;
use runne_api::{
    ProtectedCredentialRecoveryContext, ProtectedCredentialRecoveryOffer,
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2,
};
use std::{io::Read, os::unix::net::UnixStream, time::Duration};

fn bootstrap(session: u8) -> ProtectedCredentialRecoveryBootstrap {
    ProtectedCredentialRecoveryBootstrap::new([1; 32], [2; 32], [session; 32], [5; 32], [6; 32], 8)
        .unwrap()
}

pub(super) fn terminal() -> ProviderCredentialOperationSnapshotV2 {
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

fn run_peer(mut peer: UnixStream) {
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
    let context = ProtectedCredentialRecoveryContext::new(
        [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32], 7, 8,
    )
    .unwrap();
    let mut codec = ProtectedCredentialRecoveryCodec::new(&keys, context.clone());
    let operation = codec
        .decode_desktop_request(&read_frame(&mut peer).unwrap())
        .unwrap();
    assert_eq!(operation, [9; 16]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let offer =
        ProtectedCredentialRecoveryOffer::new(context, operation, [10; 32], 1, 2, 3, now, now + 30)
            .unwrap();
    write_frame(&mut peer, &codec.encode_daemon_offer(&offer, now).unwrap()).unwrap();
    // A native Begin or secret relay ACK cannot decode as recovery Accept.
    codec
        .decode_desktop_accept(&read_frame(&mut peer).unwrap(), &offer, now)
        .unwrap();
    write_frame(
        &mut peer,
        &codec.encode_daemon_terminal(&terminal()).unwrap(),
    )
    .unwrap();
}

#[test]
fn desktop_cleanup_recovery_exchanges_without_native_begin_or_secret() {
    let (mut channel, peer) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let daemon = std::thread::spawn(move || run_peer(peer));
    let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
    let recovery =
        PreparedProtectedCredentialRecovery::begin(&mut channel, &keys, bootstrap(3), [9; 16])
            .unwrap();
    assert_eq!(
        recovery.finish(&mut channel, &bootstrap(3)).unwrap(),
        terminal()
    );
    daemon.join().unwrap();
}

#[test]
fn desktop_cleanup_recovery_rejects_changed_session_before_terminal_read() {
    let (mut channel, peer) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let daemon = std::thread::spawn(move || run_peer(peer));
    let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
    let recovery =
        PreparedProtectedCredentialRecovery::begin(&mut channel, &keys, bootstrap(3), [9; 16])
            .unwrap();
    assert!(recovery.finish(&mut channel, &bootstrap(99)).is_err());
    daemon.join().unwrap();
    // The rejected call must not consume the terminal from the old channel.
    assert!(!read_frame(&mut channel).unwrap().is_empty());
}

#[test]
fn desktop_cleanup_recovery_rejects_zero_operation_without_writing() {
    let (mut channel, mut peer) = UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
    assert!(
        PreparedProtectedCredentialRecovery::begin(&mut channel, &keys, bootstrap(3), [0; 16],)
            .is_err()
    );
    let mut byte = [0];
    assert_eq!(
        peer.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(feature = "test-support")]
#[test]
fn desktop_cleanup_recovery_supervisor_requires_ready_v3_broker_facts() {
    let mut absent = test_only_absent_enrollment_supervisor().into_supervisor();
    assert!(absent.begin_protected_credential_recovery([9; 16]).is_err());
    let mut ready = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    // The fixture retains a V3 process, but no authenticated broker prelude.
    assert!(ready.begin_protected_credential_recovery([9; 16]).is_err());
}
