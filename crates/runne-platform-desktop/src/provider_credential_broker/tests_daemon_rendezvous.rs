#[cfg(not(target_os = "macos"))]
use std::io::Read as _;
use std::io::Write as _;

use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchSecret, ProviderCredentialBrokerTransferAuthority,
};

use super::*;

fn daemon_authority(
    authenticator: &CredentialBrokerTransferAuthenticator,
) -> ProviderCredentialBrokerTransferAuthority {
    ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(authenticator.clone())
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_owned_endpoint_transfers_only_to_the_bound_writer_channel() {
    let (mut daemon, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let binding = [3; 32];
    let publication_key = [4; 32];
    let receiver_thread = std::thread::spawn(move || {
        receive_daemon_owned_writer_endpoint(
            receiver,
            &receiver_authenticator,
            binding,
            publication_key,
        )
    });

    send_daemon_owned_writer_endpoint(
        sender,
        writer,
        &daemon_authority(&sender_authenticator),
        binding,
        publication_key,
    )
    .unwrap();
    let mut writer = receiver_thread.join().unwrap().unwrap().into_control();
    daemon.write_all(b"claim").unwrap();
    let mut frame = [0; 5];
    writer.read_exact(&mut frame).unwrap();
    assert_eq!(frame, *b"claim");
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_owned_endpoint_rejects_a_substituted_publication_key() {
    let (_, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let binding = [5; 32];
    let receiver_thread = std::thread::spawn(move || {
        receive_daemon_owned_writer_endpoint(receiver, &receiver_authenticator, binding, [6; 32])
    });

    // The sender must fail closed on the substituted publication key before any
    // descriptor leaves: the receiver's challenge proof commits to its own key,
    // so a mismatched key cannot authenticate the transfer.
    assert!(matches!(
        send_daemon_owned_writer_endpoint(
            sender,
            writer,
            &daemon_authority(&sender_authenticator),
            binding,
            [7; 32],
        ),
        Err(BrokerHandoffError::Rejected)
    ));
    assert!(matches!(
        receiver_thread.join().unwrap(),
        Err(BrokerHandoffError::Rejected)
    ));
}

#[cfg(unix)]
#[test]
fn daemon_owned_endpoint_rejects_zero_publication_key_before_transfer() {
    let (sender, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let (_, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([9; 32]).unwrap().derive_keys();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);

    assert_eq!(
        send_daemon_owned_writer_endpoint(
            sender,
            writer,
            &daemon_authority(&authenticator),
            [1; 32],
            [0; 32],
        ),
        Err(BrokerHandoffError::Rejected)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_owned_endpoint_rejects_a_delayed_trailing_byte_before_acceptance() {
    use std::net::Shutdown;
    use std::time::Duration;

    let (_, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (mut sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([10; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_authority = daemon_authority(&sender_authenticator);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_thread = std::thread::spawn(move || {
        let mut challenge = [0; 96];
        sender.read_exact(&mut challenge).unwrap();
        let mut response = [0; 128];
        response[..96].copy_from_slice(&challenge);
        response[96..].copy_from_slice(&[2; 32]);
        let proof = response_proof(&sender_authority, &response);
        let mut frame = [0; 160];
        frame[..128].copy_from_slice(&response);
        frame[128..].copy_from_slice(&proof);
        super::unix_descriptor::send_descriptor(&mut sender, &writer, &frame).unwrap();
        std::thread::sleep(Duration::from_millis(25));
        let _ = sender.write_all(b"x");
        let _ = sender.shutdown(Shutdown::Write);
    });

    assert!(matches!(
        receive_daemon_owned_writer_endpoint(receiver, &receiver_authenticator, [1; 32], [2; 32]),
        Err(BrokerHandoffError::Rejected)
    ));
    sender_thread.join().unwrap();
}

#[cfg(unix)]
#[test]
fn daemon_owned_endpoint_sender_requires_eof_after_the_challenge() {
    use std::net::Shutdown;

    let (sender, mut receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let (_, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([16; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_authority = daemon_authority(&sender_authenticator);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_thread = std::thread::spawn(move || {
        send_daemon_owned_writer_endpoint(sender, writer, &sender_authority, [1; 32], [2; 32])
    });
    let mut challenge = [0; 96];
    challenge[..32].copy_from_slice(&[1; 32]);
    challenge[32..64].copy_from_slice(&[3; 32]);
    let proof = challenge_proof(&receiver_authenticator, &challenge[..64], [2; 32]);
    challenge[64..].copy_from_slice(&proof);
    receiver.write_all(&challenge).unwrap();
    receiver.write_all(b"x").unwrap();
    receiver.shutdown(Shutdown::Write).unwrap();

    assert_eq!(
        sender_thread.join().unwrap(),
        Err(BrokerHandoffError::Rejected)
    );
}

fn challenge_proof(
    authenticator: &CredentialBrokerTransferAuthenticator,
    record: &[u8],
    publication_public_key: [u8; 32],
) -> [u8; 32] {
    let mut transcript =
        b"gocode/provider-credential-broker/daemon-endpoint/v1/challenge\0".to_vec();
    transcript.extend_from_slice(record);
    transcript.extend_from_slice(&publication_public_key);
    authenticator.authenticate_transfer(&transcript)
}

#[cfg(target_os = "linux")]
fn response_proof(
    authority: &ProviderCredentialBrokerTransferAuthority,
    record: &[u8],
) -> [u8; 32] {
    let mut transcript =
        b"gocode/provider-credential-broker/daemon-endpoint/v1/response\0".to_vec();
    transcript.extend_from_slice(record);
    authority.authenticate_daemon_transfer(&transcript)
}
