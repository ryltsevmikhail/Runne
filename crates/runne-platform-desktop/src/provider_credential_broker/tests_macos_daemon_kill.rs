use std::io::{Read as _, Write as _};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use runne_api::{
    CredentialBrokerTransferAuthenticator, LaunchSecret, ProviderCredentialBrokerKillBindingV1,
    ProviderCredentialBrokerKillRelinquishedProof, ProviderCredentialBrokerTransferAuthority,
};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

use super::{
    WriterProcessEvidence, capture_macos_daemon_peer_kill_capability,
    daemon_evidence::{
        receive_daemon_owned_writer_measurements, send_daemon_owned_writer_evidence,
    },
};

fn receive_measurements(
    start: [u8; 32],
) -> (
    super::ReceivedWriterProcessMeasurements,
    ProviderCredentialBrokerTransferAuthority,
    CredentialBrokerTransferAuthenticator,
    SigningKey,
) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([71; 32]).unwrap().derive_keys();
    let desktop = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let authority =
        ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(desktop.clone());
    let signing_key = SigningKey::from_bytes(&[78; 32]);
    let evidence = WriterProcessEvidence::test_only_daemon(
        start,
        [74; 32],
        [75; 32],
        [72; 32],
        [73; 32],
        signing_key.verifying_key().to_bytes(),
    );
    let evidence_desktop = desktop.clone();
    let sender = std::thread::spawn(move || {
        send_daemon_owned_writer_evidence(sender, &evidence_desktop, &evidence)
    });
    let (measurements, authority) =
        receive_daemon_owned_writer_measurements(receiver, authority, [75; 32], [72; 32], [73; 32])
            .unwrap();
    sender.join().unwrap().unwrap();
    (measurements, authority, desktop, signing_key)
}

fn transfer_authority(
    seed: u8,
) -> (
    ProviderCredentialBrokerTransferAuthority,
    CredentialBrokerTransferAuthenticator,
    SigningKey,
) {
    let keys = LaunchSecret::from_bytes([seed; 32]).unwrap().derive_keys();
    let desktop = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let signing_key = SigningKey::from_bytes(&[seed.wrapping_add(2); 32]);
    (
        ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(desktop.clone()),
        desktop,
        signing_key,
    )
}

fn relinquished(
    signing_key: &SigningKey,
    binding: ProviderCredentialBrokerKillBindingV1,
) -> ProviderCredentialBrokerKillRelinquishedProof {
    let signature = signing_key
        .sign(&binding.relinquishment_transcript())
        .to_bytes();
    ProviderCredentialBrokerKillRelinquishedProof::from_writer_signature(binding, signature)
}

fn kill_binding(
    start: [u8; 32],
    signing_key: &SigningKey,
) -> ProviderCredentialBrokerKillBindingV1 {
    ProviderCredentialBrokerKillBindingV1::new(
        start,
        [74; 32],
        [75; 32],
        [72; 32],
        [73; 32],
        signing_key.verifying_key().to_bytes(),
    )
}

const CHILD_SOCKET: &str = "GOCODE_MACOS_PEER_KILL_SOCKET";
const CHILD_TRANSFER: &str = "GOCODE_MACOS_PEER_KILL_TRANSFER";
const CHILD_TEST: &str =
    "provider_credential_broker::tests_macos_daemon_kill::macos_peer_kill_writer_child";

fn daemon_connected_writer() -> (UnixStream, std::process::Child) {
    // A CI TMPDIR can exceed sockaddr_un.sun_path before the socket name is added.
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let socket = directory.path().join("writer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_SOCKET, &socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (daemon, _) = listener.accept().unwrap();
    (daemon, child)
}

#[test]
fn macos_peer_kill_writer_child() {
    if std::env::var_os(CHILD_TRANSFER).is_some() {
        let mut endpoint = UnixStream::from(receive_stdin_descriptor());
        endpoint.write_all(b"R").unwrap();
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    let Ok(socket) = std::env::var(CHILD_SOCKET) else {
        return;
    };
    let _writer = UnixStream::connect(socket).unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

fn receive_stdin_descriptor() -> OwnedFd {
    let stdin = std::io::stdin();
    let mut byte = [0_u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut byte)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    recvmsg(&stdin, &mut iov, &mut ancillary, RecvFlags::empty()).unwrap();
    let mut descriptors = ancillary.drain().flat_map(|message| match message {
        RecvAncillaryMessage::ScmRights(rights) => rights.collect(),
        _ => Vec::new(),
    });
    let descriptor = descriptors.next().unwrap();
    assert!(descriptors.next().is_none());
    descriptor
}

#[test]
fn local_peer_token_tracks_the_writer_that_received_the_daemon_endpoint() {
    let (mut daemon, writer) = UnixStream::pair().unwrap();
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_TRANSFER, "1")
        .stdin(Stdio::from(OwnedFd::from(receiver)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    super::unix_descriptor::send_descriptor(&mut sender, &writer, b"X").unwrap();
    drop(writer);
    let mut ready = [0; 1];
    daemon.read_exact(&mut ready).unwrap();
    assert_eq!(ready, *b"R");
    let pid = NonZeroU32::new(child.id()).unwrap();
    let start = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
        .unwrap()
        .digest();
    let (measurements, authority, _desktop, signing_key) = receive_measurements(start);
    let kill_binding = kill_binding(start, &signing_key);

    let pending =
        capture_macos_daemon_peer_kill_capability(&daemon, measurements, &authority).unwrap();
    let relinquished = relinquished(&signing_key, kill_binding);
    let capability = pending
        .enable_after_relinquished(&authority, &relinquished)
        .unwrap();
    capability.terminate_exact_peer().unwrap();
    assert!(!child.wait().unwrap().success());
}

#[test]
fn local_peer_token_capability_kills_only_the_authenticated_connected_writer() {
    let (daemon, mut writer) = daemon_connected_writer();
    let pid = NonZeroU32::new(writer.id()).unwrap();
    let start = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
        .unwrap()
        .digest();
    let (measurements, authority, _desktop, signing_key) = receive_measurements(start);
    let kill_binding = kill_binding(start, &signing_key);

    let pending =
        capture_macos_daemon_peer_kill_capability(&daemon, measurements, &authority).unwrap();
    let relinquished = relinquished(&signing_key, kill_binding);
    let capability = pending
        .enable_after_relinquished(&authority, &relinquished)
        .unwrap();
    capability.terminate_exact_peer().unwrap();
    assert!(!writer.wait().unwrap().success());
}

#[test]
fn local_peer_token_capability_rejects_a_mismatched_authenticated_writer_start() {
    let (daemon, mut writer) = daemon_connected_writer();
    let (measurements, authority, _, _) = receive_measurements([76; 32]);

    assert!(capture_macos_daemon_peer_kill_capability(&daemon, measurements, &authority).is_err());
    writer.kill().unwrap();
    writer.wait().unwrap();
}

#[test]
fn captured_capability_cannot_signal_before_desktop_relinquishes() {
    let (daemon, mut writer) = daemon_connected_writer();
    let pid = NonZeroU32::new(writer.id()).unwrap();
    let start = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
        .unwrap()
        .digest();
    let (measurements, authority, desktop, signing_key) = receive_measurements(start);
    let kill_binding = kill_binding(start, &signing_key);

    {
        let pending =
            capture_macos_daemon_peer_kill_capability(&daemon, measurements, &authority).unwrap();
        let ready = pending.issue_ready(&authority).unwrap();
        assert!(ready.verifies(&desktop, &kill_binding));
    }

    assert!(writer.try_wait().unwrap().is_none());
    writer.kill().unwrap();
    writer.wait().unwrap();
}

#[test]
fn substituted_relinquishment_proof_cannot_enable_daemon_kill() {
    let (daemon, mut writer) = daemon_connected_writer();
    let pid = NonZeroU32::new(writer.id()).unwrap();
    let start = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
        .unwrap()
        .digest();
    let (substituted_measurements, _, _, _) = receive_measurements(start);
    let (substituted_authority, _, substituted_signing_key) = transfer_authority(77);
    assert!(
        capture_macos_daemon_peer_kill_capability(
            &daemon,
            substituted_measurements,
            &substituted_authority,
        )
        .is_err()
    );
    let (measurements, authority, _, signing_key) = receive_measurements(start);
    let kill_binding = kill_binding(start, &signing_key);
    let pending =
        capture_macos_daemon_peer_kill_capability(&daemon, measurements, &authority).unwrap();
    let proof = relinquished(&substituted_signing_key, kill_binding);
    let (daemon_control, mut desktop_control) = UnixStream::pair().unwrap();
    let responder = std::thread::spawn(move || {
        let mut ready = Vec::new();
        desktop_control.read_to_end(&mut ready).unwrap();
        desktop_control.write_all(&proof.to_exact_wire()).unwrap();
        desktop_control.shutdown(Shutdown::Write).unwrap();
    });

    assert!(
        pending
            .complete_desktop_relinquishment(daemon_control, &authority)
            .is_err()
    );
    responder.join().unwrap();
    assert!(writer.try_wait().unwrap().is_none());
    writer.kill().unwrap();
    writer.wait().unwrap();
}

#[test]
fn local_peer_token_capability_fails_closed_when_runtime_symbol_is_unavailable() {
    let (daemon, mut writer) = daemon_connected_writer();
    let pid = NonZeroU32::new(writer.id()).unwrap();
    let start = runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
        .unwrap()
        .digest();
    let (measurements, authority, _, _) = receive_measurements(start);

    assert!(matches!(
        super::macos_daemon_kill::test_only_capture_without_runtime_symbol(
            &daemon,
            measurements,
            &authority
        ),
        Err(runne_platform_ports::provider_credential_broker::BrokerHandoffError::Unavailable)
    ));
    writer.kill().unwrap();
    writer.wait().unwrap();
}
