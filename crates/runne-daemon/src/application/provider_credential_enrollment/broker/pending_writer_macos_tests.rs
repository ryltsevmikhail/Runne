use std::io::{Read as _, Write as _};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use ed25519_dalek::{Signer as _, SigningKey};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

use super::*;

const CHILD_TRANSFER: &str = "GOCODE_DAEMON_MACOS_WRITER_TRANSFER";
const CHILD_TEST: &str = "application::provider_credential_enrollment::broker::pending_writer::tests::macos_tests::authenticated_writer_becomes_daemon_killable_only_after_kernel_peer_capture";

#[test]
fn authenticated_writer_becomes_daemon_killable_only_after_kernel_peer_capture() {
    if std::env::var_os(CHILD_TRANSFER).is_some() {
        let mut endpoint = UnixStream::from(receive_stdin_descriptor());
        endpoint.write_all(b"R").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(30));
        return;
    }
    let fixture = binding_fixture(4_000_000_000);
    let (sealed, sender_authenticator) = transfer_authority(&fixture.issuer, [31; 32], [4; 32]);
    let channel = [32; 32];
    let (daemon_endpoint, writer_endpoint) = UnixStream::pair().unwrap();
    let authority = DaemonBrokerAuthority::for_test_endpoint(channel, daemon_endpoint);
    let publication_key = authority.publication_public_key();
    let binding = PendingBrokerRendezvousBinding::new(
        &fixture.operation,
        &fixture.authority,
        &fixture.proof,
        100,
    )
    .unwrap();
    let awaiting = AwaitingVerifiedWriter {
        binding,
        authority,
        transfer_authority: sealed,
    };
    let (mut transfer_sender, transfer_writer) = UnixStream::pair().unwrap();
    let mut writer = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_TRANSFER, "1")
        .stdin(Stdio::from(OwnedFd::from(transfer_writer)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    send_descriptor(&mut transfer_sender, &writer_endpoint);
    drop(writer_endpoint);
    let mut ready = [0; 1];
    awaiting
        .authority
        .endpoint()
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(ready, *b"R");
    let start =
        runne_platform_desktop::provider_credential_broker::test_only_observe_process_start(
            writer.id(),
        )
        .unwrap();
    let release_tuple = fixture.release_tuple;
    let signing_key = SigningKey::from_bytes(&[33; 32]);
    let writer_kill_public_key = signing_key.verifying_key().to_bytes();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let evidence_authenticator = sender_authenticator.clone();
    let sender_thread = std::thread::spawn(move || {
        send_test_daemon_owned_writer_evidence(
            sender,
            &evidence_authenticator,
            [
                start,
                [12; 32],
                release_tuple,
                channel,
                publication_key,
                writer_kill_public_key,
            ],
        )
    });

    let admitted = awaiting
        .receive_writer_evidence(
            receiver,
            &fixture.operation,
            &fixture.authority,
            &fixture.proof,
            100,
        )
        .unwrap();
    sender_thread.join().unwrap().unwrap();
    let captured = admitted.capture_macos_kill_capability().unwrap();
    let kill_binding = runne_api::ProviderCredentialBrokerKillBindingV1::new(
        start,
        [12; 32],
        release_tuple,
        channel,
        publication_key,
        writer_kill_public_key,
    );
    let (daemon_control, mut desktop_control) = UnixStream::pair().unwrap();
    let desktop_thread = std::thread::spawn(move || {
        let mut ready_wire = Vec::new();
        desktop_control.read_to_end(&mut ready_wire).unwrap();
        let ready = runne_platform_desktop::provider_credential_broker::MacOsPeerKillReadyProof::from_authenticated_wire(
            &ready_wire,
            &sender_authenticator,
            &kill_binding,
        )
        .unwrap();
        assert!(ready.verifies(&sender_authenticator, &kill_binding));
        let signature = signing_key
            .sign(&kill_binding.relinquishment_transcript())
            .to_bytes();
        let relinquished =
            runne_api::ProviderCredentialBrokerKillRelinquishedProof::from_writer_signature(
                kill_binding,
                signature,
            );
        desktop_control
            .write_all(&relinquished.to_exact_wire())
            .unwrap();
        desktop_control.shutdown(Shutdown::Write).unwrap();
    });
    let killable = captured
        .complete_ownership_exchange(daemon_control)
        .unwrap();
    desktop_thread.join().unwrap();
    killable.terminate_exact_writer().unwrap();
    assert!(!writer.wait().unwrap().success());
}

fn send_descriptor(transport: &mut UnixStream, endpoint: &UnixStream) {
    let descriptors = [endpoint.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    assert_eq!(
        sendmsg(
            transport,
            &[std::io::IoSlice::new(b"X")],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap(),
        1
    );
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
