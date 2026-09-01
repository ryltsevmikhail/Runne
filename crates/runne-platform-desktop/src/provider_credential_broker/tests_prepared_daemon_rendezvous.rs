use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchSecret, ProviderCredentialBrokerTransferAuthority,
};
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::*;

fn daemon_authority(
    authenticator: &CredentialBrokerTransferAuthenticator,
) -> ProviderCredentialBrokerTransferAuthority {
    ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(authenticator.clone())
}

#[cfg(target_os = "macos")]
#[test]
fn prepared_daemon_endpoint_reaches_the_fixed_writer_without_tauri_receiving_it() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("writer-fixture");
    let received_path = directory.path().join("received");
    std::fs::write(
        &executable,
        "#!/bin/sh\nout=${0%/*}/received\n/bin/dd bs=160 count=1 of=\"$out\" 2>/dev/null || exit 12\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact::new(
        executable, [1; 32], [2; 32],
    )
    .unwrap();
    let spec =
        runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec::new(artifact);
    let (daemon, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([31; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_authority = daemon_authority(&sender_authenticator);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let binding = [32; 32];
    let publication_key = [33; 32];
    let sender_thread = std::thread::spawn(move || {
        send_daemon_owned_writer_endpoint(
            sender,
            writer,
            &sender_authority,
            binding,
            publication_key,
        )
    });

    let prepared = prepare_daemon_owned_writer_endpoint_handoff(
        receiver,
        &receiver_authenticator,
        binding,
        publication_key,
    )
    .unwrap();
    let mut process = unix_daemon::spawn_test_macos_prepared_writer(&spec, prepared).unwrap();

    sender_thread.join().unwrap().unwrap();
    process.reap_retained_child().unwrap();
    let frame = std::fs::read(received_path).unwrap();
    assert_eq!(frame.len(), 160);
    assert_eq!(&frame[..32], &binding);
    assert_eq!(&frame[96..128], &publication_key);
    assert_ne!(&frame[128..], &[0; 32]);
    drop(daemon);
}

#[cfg(target_os = "macos")]
#[test]
fn prepared_writer_does_not_inherit_a_non_close_on_exec_sentinel_fd() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("writer-fixture");
    let marker = directory.path().join("marker");
    std::fs::write(
        &executable,
        "#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = \"__provider-credential-broker-v1\" ] || exit 16\nfor fd in $(/usr/bin/jot 21 200); do [ -e /dev/fd/$fd ] && exit 17; done\n: > \"${0%/*}/marker\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact::new(
        executable, [1; 32], [2; 32],
    )
    .unwrap();
    let spec =
        runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec::new(artifact);
    let sentinel = std::fs::File::open("/dev/null").unwrap();
    let sentinel = rustix::io::fcntl_dupfd_cloexec(&sentinel, 200).unwrap();
    rustix::io::fcntl_setfd(&sentinel, rustix::io::FdFlags::empty()).unwrap();
    let (receiver, _daemon) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([38; 32]).unwrap().derive_keys();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let prepared =
        prepare_daemon_owned_writer_endpoint_handoff(receiver, &authenticator, [1; 32], [2; 32])
            .unwrap();

    let mut process = unix_daemon::spawn_test_macos_prepared_writer(&spec, prepared).unwrap();

    process.reap_retained_child().unwrap();
    assert!(marker.exists());
}

#[cfg(unix)]
#[test]
fn prepared_daemon_endpoint_rejects_zero_binding_before_the_challenge() {
    let (receiver, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([34; 32]).unwrap().derive_keys();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);

    assert!(matches!(
        prepare_daemon_owned_writer_endpoint_handoff(receiver, &authenticator, [0; 32], [1; 32]),
        Err(BrokerHandoffError::Rejected)
    ));
}

#[cfg(unix)]
#[test]
fn prepared_daemon_endpoint_tampering_is_rejected_before_writer_handoff() {
    let (_, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let sender_keys = LaunchSecret::from_bytes([35; 32]).unwrap().derive_keys();
    let receiver_keys = LaunchSecret::from_bytes([36; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&sender_keys);
    let sender_authority = daemon_authority(&sender_authenticator);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&receiver_keys);
    let sender_thread = std::thread::spawn(move || {
        send_daemon_owned_writer_endpoint(sender, writer, &sender_authority, [1; 32], [2; 32])
    });

    let prepared = prepare_daemon_owned_writer_endpoint_handoff(
        receiver,
        &receiver_authenticator,
        [1; 32],
        [2; 32],
    )
    .unwrap();

    assert!(matches!(
        sender_thread.join().unwrap(),
        Err(BrokerHandoffError::Rejected)
    ));
    drop(prepared);
}

#[cfg(unix)]
#[test]
fn prepared_daemon_endpoint_rejects_substituted_publication_key_before_response() {
    let (_, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([37; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_authority = daemon_authority(&sender_authenticator);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_thread = std::thread::spawn(move || {
        send_daemon_owned_writer_endpoint(sender, writer, &sender_authority, [1; 32], [2; 32])
    });

    let prepared = prepare_daemon_owned_writer_endpoint_handoff(
        receiver,
        &receiver_authenticator,
        [1; 32],
        [3; 32],
    )
    .unwrap();

    assert!(matches!(
        sender_thread.join().unwrap(),
        Err(BrokerHandoffError::Rejected)
    ));
    drop(prepared);
}
