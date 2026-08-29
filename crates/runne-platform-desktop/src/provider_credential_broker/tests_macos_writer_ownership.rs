use std::io::{Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

use super::{
    capture_macos_daemon_peer_kill_capability,
    daemon_evidence::receive_daemon_owned_writer_measurements,
    macos_writer_admission::{
        VerifiedMacOsWriterProcess, prepare_retained_writer_image, test_apple_launch,
    },
    unix::UnixRetainedWriterProcess,
};

const CHILD_TEST: &str = "provider_credential_broker::tests_macos_writer_ownership::writer_receives_daemon_endpoint_after_spawn";

#[test]
fn writer_receives_daemon_endpoint_after_spawn() {
    if std::env::var_os("GOCODE_WRITER_OWNERSHIP_CHILD").is_none() {
        return;
    }
    let stdin = std::io::stdin();
    let mut byte = [0_u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut byte)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    recvmsg(&stdin, &mut iov, &mut ancillary, RecvFlags::empty()).unwrap();
    let descriptor = ancillary
        .drain()
        .find_map(|message| match message {
            RecvAncillaryMessage::ScmRights(mut rights) => rights.next(),
            _ => None,
        })
        .unwrap();
    let mut endpoint = UnixStream::from(descriptor);
    endpoint.write_all(b"R").unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[expect(
    clippy::zombie_processes,
    reason = "the retained writer wrapper becomes the sole reap owner below"
)]
fn desktop_relinquishes_before_daemon_can_kill_the_exact_writer() {
    let executable = std::env::current_exe().unwrap();
    let release = [84; 32];
    let launch = test_apple_launch(&executable, release).unwrap();
    let image = prepare_retained_writer_image(&launch).unwrap();
    let (mut bootstrap, child_bootstrap) = UnixStream::pair().unwrap();
    let (mut daemon, writer_endpoint) = UnixStream::pair().unwrap();
    let child = Command::new(&executable)
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env("GOCODE_WRITER_OWNERSHIP_CHILD", "1")
        .stdin(Stdio::from(OwnedFd::from(child_bootstrap)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    super::unix_descriptor::send_descriptor(&mut bootstrap, &writer_endpoint, b"X").unwrap();
    drop(writer_endpoint);
    let mut ready = [0; 1];
    daemon.read_exact(&mut ready).unwrap();
    assert_eq!(ready, *b"R");

    let process = UnixRetainedWriterProcess::from_pid(nix::unistd::Pid::from_raw(
        i32::try_from(child.id()).unwrap(),
    ))
    .unwrap();
    let verified =
        VerifiedMacOsWriterProcess::admit(process, launch, image, [85; 32], [86; 32]).unwrap();
    let keys = LaunchSecret::from_bytes([87; 32]).unwrap().derive_keys();
    let desktop = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let authority =
        runne_api::ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(
            desktop.clone(),
        );
    let (evidence_sender, evidence_receiver) = UnixStream::pair().unwrap();
    let desktop_sender = desktop;
    let evidence_thread = std::thread::spawn(move || {
        let pending = verified
            .transfer_evidence_to_daemon(evidence_sender, &desktop_sender)
            .unwrap();
        (pending, desktop_sender)
    });
    let (measurements, authority) = receive_daemon_owned_writer_measurements(
        evidence_receiver,
        authority,
        release,
        [85; 32],
        [86; 32],
    )
    .unwrap();
    let (pending, desktop) = evidence_thread.join().unwrap();
    let daemon_pending =
        capture_macos_daemon_peer_kill_capability(&daemon, measurements, &authority).unwrap();
    let ready = daemon_pending.issue_ready(&authority).unwrap();
    let (reap_owner, relinquished) = pending.accept_daemon_kill_ready(&ready, &desktop).unwrap();
    let kill = daemon_pending
        .enable_after_relinquished(&authority, &relinquished)
        .unwrap();
    kill.terminate_exact_peer().unwrap();
    reap_owner.reap_exact_writer().unwrap();
}
