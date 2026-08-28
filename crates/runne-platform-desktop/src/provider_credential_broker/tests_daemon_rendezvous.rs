use std::io::{Read as _, Write as _};

use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};

use super::*;

#[cfg(unix)]
#[test]
fn daemon_owned_endpoint_transfers_only_to_the_bound_writer_channel() {
    let (mut daemon, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (mut sender, mut receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let binding = [3; 32];
    let receiver_thread = std::thread::spawn(move || {
        receive_daemon_owned_writer_endpoint(&mut receiver, &receiver_authenticator, binding)
    });

    send_daemon_owned_writer_endpoint(&mut sender, writer, &sender_authenticator, binding).unwrap();
    let mut writer = receiver_thread.join().unwrap().unwrap().into_control();
    daemon.write_all(b"claim").unwrap();
    let mut frame = [0; 5];
    writer.read_exact(&mut frame).unwrap();
    assert_eq!(frame, *b"claim");
}

#[cfg(unix)]
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
    let (mut sender, mut receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let binding = [4; 32];
    let receiver_thread = std::thread::spawn(move || {
        receive_daemon_owned_writer_endpoint(&mut receiver, &receiver_authenticator, binding)
    });
    send_daemon_owned_writer_endpoint(&mut sender, writer, &sender_authenticator, binding).unwrap();
    let endpoint = receiver_thread.join().unwrap().unwrap();
    let (mut endpoints, mut process, evidence) =
        spawn_unix_writer_from_daemon_endpoint(&spec, endpoint).unwrap();

    daemon.write_all(b"control\n").unwrap();
    let mut reply = [0; 5];
    daemon.read_exact(&mut reply).unwrap();
    assert_eq!(reply, *b"reply");
    assert_eq!(evidence.channel_binding(), binding);
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
