use std::io::Write as _;
use std::net::Shutdown;

use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};

use super::*;

#[cfg(unix)]
#[test]
fn legacy_writer_control_rejects_an_untagged_daemon_endpoint_challenge_replay() {
    let (mut tauri, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (control, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([21; 32]).unwrap().derive_keys();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let channel = [3; 32];
    let mut endpoints = UnixWriterBrokerEndpoints {
        control: Some(control),
        secret: None,
        channel_binding: channel,
    };
    let evidence = WriterProcessEvidence::test_only([1; 32], [2; 32], channel);
    let mut challenge = [0; 96];
    challenge[..32].copy_from_slice(&channel);
    challenge[32..64].copy_from_slice(&[4; 32]);
    let proof = authenticator.authenticate_transfer(&challenge[..64]);
    challenge[64..].copy_from_slice(&proof);
    peer.write_all(&challenge).unwrap();

    assert_eq!(
        transfer_unix_writer_control(&mut tauri, &mut endpoints, &authenticator, &evidence),
        Err(BrokerHandoffError::Rejected)
    );
}

#[cfg(unix)]
#[test]
fn daemon_endpoint_rejects_an_untagged_legacy_writer_control_challenge_replay() {
    let (sender, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (_, endpoint) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([22; 32]).unwrap().derive_keys();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let mut challenge = [0; 96];
    challenge[..32].copy_from_slice(&[5; 32]);
    challenge[32..64].copy_from_slice(&[6; 32]);
    let proof = authenticator.authenticate_transfer(&challenge[..64]);
    challenge[64..].copy_from_slice(&proof);
    peer.write_all(&challenge).unwrap();
    peer.shutdown(Shutdown::Write).unwrap();

    assert_eq!(
        send_daemon_owned_writer_endpoint(sender, endpoint, &authenticator, [5; 32], [7; 32]),
        Err(BrokerHandoffError::Rejected)
    );
}
