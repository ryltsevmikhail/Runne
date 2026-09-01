#![cfg(test)]

use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::time::Duration;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use crate::writer_endpoint_handoff::MacOsUntrustedWriterEndpointHandoffV1;

pub(super) const FRAME_BYTES: usize = 160;
pub(super) const RECEIVE_BUDGET: Duration = Duration::from_secs(1);
pub(super) const SHORT_DEADLINE: Duration = Duration::from_millis(40);

pub(super) fn valid_frame() -> [u8; FRAME_BYTES] {
    let mut frame = [0; FRAME_BYTES];
    frame[..32].fill(1);
    frame[96..128].fill(2);
    frame
}

pub(super) fn receive_exact(frame: &[u8; FRAME_BYTES]) -> MacOsUntrustedWriterEndpointHandoffV1 {
    let (sender, receiver) = UnixStream::pair().expect("transport pair");
    let (offered, _) = UnixStream::pair().expect("offered endpoint");
    send_with_descriptors(&sender, frame, &[offered.as_fd()]);
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown writer");
    crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET)
        .expect("exact handoff")
}

pub(super) fn send_with_descriptors(
    sender: &impl std::os::fd::AsFd,
    bytes: &[u8],
    descriptors: &[BorrowedFd<'_>],
) {
    let sent =
        crate::writer_endpoint_handoff::test_only_send_with_descriptors(sender, bytes, descriptors)
            .expect("sendmsg");
    assert_eq!(sent, bytes.len());
}

pub(super) fn write_without_descriptors(sender: &mut UnixStream, bytes: &[u8]) {
    sender.write_all(bytes).expect("write bytes");
}

pub(super) fn send_datagram_with_descriptor(
    sender: &UnixDatagram,
    bytes: &[u8],
    descriptor: BorrowedFd<'_>,
) {
    send_with_descriptors(sender, bytes, &[descriptor]);
}

pub(super) fn assert_peer_closed(mut peer: UnixStream) {
    let mut descriptors = [PollFd::new(peer.as_fd(), PollFlags::POLLIN)];
    let ready = poll(&mut descriptors, PollTimeout::from(1_000_u16)).expect("poll peer EOF");
    assert_eq!(ready, 1, "peer copy remained live");
    let mut byte = [0];
    let observed = peer.read(&mut byte);
    assert!(
        matches!(observed, Ok(0)),
        "peer copy remained live: {observed:?}"
    );
}
