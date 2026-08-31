use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use super::bootstrap::receive_prepared_daemon_endpoint;

const RESPONSE_BYTES: usize = 160;

#[test]
fn prepared_daemon_endpoint_requires_one_descriptor() {
    let (mut sender, mut receiver) = UnixStream::pair().expect("transport pair");
    sender
        .write_all(&prepared_response())
        .expect("write response without descriptor");
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("close sender");

    assert!(receive_prepared_daemon_endpoint(&mut receiver).is_err());
}

#[test]
fn prepared_daemon_endpoint_rejects_trailing_bytes() {
    let (mut sender, mut receiver) = UnixStream::pair().expect("transport pair");
    let mut response = prepared_response().to_vec();
    response.push(1);
    sender
        .write_all(&response)
        .expect("write trailing response");
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("close sender");

    assert!(receive_prepared_daemon_endpoint(&mut receiver).is_err());
}

#[test]
fn prepared_daemon_endpoint_rejects_multiple_descriptors() {
    let (mut sender, mut receiver) = UnixStream::pair().expect("transport pair");
    let (first, _) = UnixStream::pair().expect("first endpoint");
    let (second, _) = UnixStream::pair().expect("second endpoint");
    send_response(
        &mut sender,
        &prepared_response(),
        &[first.as_fd(), second.as_fd()],
    );
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("close sender");

    assert!(receive_prepared_daemon_endpoint(&mut receiver).is_err());
}

#[test]
fn prepared_daemon_endpoint_rejects_descriptors_split_across_frame_reads() {
    let (mut sender, mut receiver) = UnixStream::pair().expect("transport pair");
    let (first, _) = UnixStream::pair().expect("first endpoint");
    let (second, _) = UnixStream::pair().expect("second endpoint");
    let response = prepared_response();
    send_segment(&mut sender, &response[..1], &[first.as_fd()]);
    send_segment(&mut sender, &response[1..], &[second.as_fd()]);
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("close sender");

    assert!(receive_prepared_daemon_endpoint(&mut receiver).is_err());
}

#[test]
fn prepared_daemon_endpoint_accepts_exact_response_and_one_descriptor() {
    let (mut sender, mut receiver) = UnixStream::pair().expect("transport pair");
    let (endpoint, _) = UnixStream::pair().expect("endpoint");
    send_response(&mut sender, &prepared_response(), &[endpoint.as_fd()]);
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("close sender");

    let endpoint = receive_prepared_daemon_endpoint(&mut receiver).expect("accepted endpoint");
    assert!(endpoint.has_close_on_exec());
}

#[test]
fn prepared_daemon_endpoint_rejects_zero_binding_or_publication_key() {
    for range in [0..32, 96..128] {
        let (mut sender, mut receiver) = UnixStream::pair().expect("transport pair");
        let (endpoint, _) = UnixStream::pair().expect("endpoint");
        let mut response = prepared_response();
        response[range].fill(0);
        send_response(&mut sender, &response, &[endpoint.as_fd()]);
        sender
            .shutdown(std::net::Shutdown::Write)
            .expect("close sender");

        assert!(receive_prepared_daemon_endpoint(&mut receiver).is_err());
    }
}

fn prepared_response() -> [u8; RESPONSE_BYTES] {
    let mut response = [0; RESPONSE_BYTES];
    response[..32].fill(1);
    response[96..128].fill(2);
    response
}

fn send_response(
    transport: &mut UnixStream,
    response: &[u8; RESPONSE_BYTES],
    descriptors: &[std::os::fd::BorrowedFd<'_>],
) {
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(descriptors)));
    let sent = sendmsg(
        transport,
        &[std::io::IoSlice::new(response)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .expect("send response");
    assert_eq!(sent, RESPONSE_BYTES);
}

fn send_segment(
    transport: &mut UnixStream,
    frame: &[u8],
    descriptors: &[std::os::fd::BorrowedFd<'_>],
) {
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(descriptors)));
    let sent = sendmsg(
        transport,
        &[std::io::IoSlice::new(frame)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .expect("send response segment");
    assert_eq!(sent, frame.len());
}
