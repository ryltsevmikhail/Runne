use std::io::{Read as _, Write as _};

use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};

use super::*;

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
        &sender_authenticator,
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

    send_daemon_owned_writer_endpoint(sender, writer, &sender_authenticator, binding, [7; 32])
        .unwrap();
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
        send_daemon_owned_writer_endpoint(sender, writer, &authenticator, [1; 32], [0; 32],),
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
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_thread = std::thread::spawn(move || {
        let mut challenge = [0; 96];
        sender.read_exact(&mut challenge).unwrap();
        let mut response = [0; 128];
        response[..96].copy_from_slice(&challenge);
        response[96..].copy_from_slice(&[2; 32]);
        let proof = response_proof(&sender_authenticator, &response);
        let mut frame = [0; 160];
        frame[..128].copy_from_slice(&response);
        frame[128..].copy_from_slice(&proof);
        super::unix_transfer::send_descriptor(&mut sender, &writer, &frame).unwrap();
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
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_thread = std::thread::spawn(move || {
        send_daemon_owned_writer_endpoint(sender, writer, &sender_authenticator, [1; 32], [2; 32])
    });
    let mut challenge = [0; 96];
    challenge[..32].copy_from_slice(&[1; 32]);
    challenge[32..64].copy_from_slice(&[3; 32]);
    let proof = challenge_proof(&receiver_authenticator, &challenge[..64]);
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
) -> [u8; 32] {
    tagged_proof(
        authenticator,
        b"gocode/provider-credential-broker/daemon-endpoint/v1/challenge\0",
        record,
    )
}

#[cfg(target_os = "linux")]
fn response_proof(
    authenticator: &CredentialBrokerTransferAuthenticator,
    record: &[u8],
) -> [u8; 32] {
    tagged_proof(
        authenticator,
        b"gocode/provider-credential-broker/daemon-endpoint/v1/response\0",
        record,
    )
}

fn tagged_proof(
    authenticator: &CredentialBrokerTransferAuthenticator,
    tag: &[u8],
    record: &[u8],
) -> [u8; 32] {
    let mut transcript = tag.to_vec();
    transcript.extend_from_slice(record);
    authenticator.authenticate_transfer(&transcript)
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_owned_writer_launch_has_one_inherited_channel_and_zero_secret_fds() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("writer-fixture");
    std::fs::write(
        &executable,
        "#!/bin/sh\nIFS= read -r control || exit 12\nIFS= read -r secret <&1 2>/dev/null && exit 13\n[ \"$control\" = control ] || exit 14\nprintf reply >&2\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact::new(
        executable, [1; 32], [2; 32],
    )
    .unwrap();
    let spec =
        runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec::new(artifact);
    let (mut daemon, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let binding = [4; 32];
    let publication_key = [5; 32];
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
        &sender_authenticator,
        binding,
        publication_key,
    )
    .unwrap();
    let endpoint = receiver_thread.join().unwrap().unwrap();
    let (mut endpoints, mut process, evidence) =
        spawn_unix_writer_from_daemon_endpoint(&spec, endpoint).unwrap();

    daemon.write_all(b"control\n").unwrap();
    let mut reply = [0; 5];
    daemon.read_exact(&mut reply).unwrap();
    assert_eq!(reply, *b"reply");
    assert!(evidence.matches_daemon_owned_launch(&spec, binding, publication_key));
    assert_eq!(
        endpoints.send_control(b"tauri-control"),
        Err(BrokerHandoffError::Rejected)
    );
    assert_eq!(
        endpoints.send_secret(
            runne_platform_ports::provider_credential_prompt::SecureCredentialMaterial::new(
                b"secret".to_vec(),
            )
            .unwrap()
            .into_pipe_bytes(),
        ),
        Err(BrokerHandoffError::Rejected)
    );
    process.reap_retained_child().unwrap();
}

#[cfg(unix)]
#[test]
fn daemon_fixture_emits_no_reply_when_stdout_contains_readable_secret_data() {
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("writer-fixture");
    std::fs::write(
        &executable,
        "#!/bin/sh\nIFS= read -r control || exit 12\nIFS= read -r secret <&1 2>/dev/null && exit 13\n[ \"$control\" = control ] || exit 14\nprintf reply >&2\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (mut daemon, child_control) = std::os::unix::net::UnixStream::pair().unwrap();
    let child_stderr = child_control.try_clone().unwrap();
    let (mut readable_stdout, child_stdout) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut child = Command::new(executable)
        .stdin(Stdio::from(OwnedFd::from(child_control)))
        .stderr(Stdio::from(OwnedFd::from(child_stderr)))
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .spawn()
        .unwrap();

    daemon.write_all(b"control\n").unwrap();
    readable_stdout.write_all(b"secret\n").unwrap();
    let status = child.wait().unwrap();
    let mut reply = [0; 1];

    assert_eq!(status.code(), Some(13));
    assert_eq!(daemon.read(&mut reply).unwrap(), 0);
}
