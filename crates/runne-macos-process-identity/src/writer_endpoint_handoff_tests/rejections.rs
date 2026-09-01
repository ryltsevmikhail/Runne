#![cfg(test)]

use std::os::fd::AsFd as _;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;

use super::support::{FRAME_BYTES, RECEIVE_BUDGET, assert_peer_closed};
use super::support::{send_datagram_with_descriptor, send_with_descriptors};
use super::support::{valid_frame, write_without_descriptors};

#[test]
fn early_eof_at_zero_or_159_bytes_is_rejected() {
    for length in [0, FRAME_BYTES - 1] {
        let (mut sender, receiver) = UnixStream::pair().expect("transport pair");
        write_without_descriptors(&mut sender, &valid_frame()[..length]);
        sender
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown writer");
        assert!(
            crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET).is_err(),
            "accepted early EOF at {length}"
        );
    }
}

#[test]
fn trailing_byte_or_descriptor_with_trailing_byte_is_rejected() {
    for descriptor_on_trailer in [false, true] {
        let (mut sender, receiver) = UnixStream::pair().expect("transport pair");
        let (first, first_peer) = UnixStream::pair().expect("first endpoint");
        send_with_descriptors(&sender, &valid_frame(), &[first.as_fd()]);
        let mut peers = vec![first_peer];
        if descriptor_on_trailer {
            let (second, second_peer) = UnixStream::pair().expect("second endpoint");
            send_with_descriptors(&sender, &[9], &[second.as_fd()]);
            drop(second);
            peers.push(second_peer);
        } else {
            write_without_descriptors(&mut sender, &[9]);
        }
        drop(first);
        sender
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown writer");

        assert!(
            crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET).is_err()
        );
        for peer in peers {
            assert_peer_closed(peer);
        }
    }
}

#[test]
fn zero_two_or_split_descriptors_are_rejected_and_closed() {
    let (mut sender, receiver) = UnixStream::pair().expect("no descriptor transport");
    write_without_descriptors(&mut sender, &valid_frame());
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown writer");
    assert!(crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET).is_err());

    let (sender, receiver) = UnixStream::pair().expect("two descriptor transport");
    let pairs: Vec<_> = (0..2)
        .map(|_| UnixStream::pair().expect("offered pair"))
        .collect();
    let descriptors: Vec<_> = pairs.iter().map(|(offered, _)| offered.as_fd()).collect();
    send_with_descriptors(&sender, &valid_frame(), &descriptors);
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown writer");
    assert!(crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET).is_err());

    let (sender, receiver) = UnixStream::pair().expect("split descriptor transport");
    let (first, first_peer) = UnixStream::pair().expect("first endpoint");
    let (second, second_peer) = UnixStream::pair().expect("second endpoint");
    let frame = valid_frame();
    send_with_descriptors(&sender, &frame[..1], &[first.as_fd()]);
    send_with_descriptors(&sender, &frame[1..], &[second.as_fd()]);
    drop((first, second));
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown writer");
    assert!(crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET).is_err());
    assert_peer_closed(first_peer);
    assert_peer_closed(second_peer);
}

const CTRUNC_CHILD: &str = "RUNNE_TEST_WRITER_HANDOFF_CTRUNC_ABORT";
// Current Darwin accepts 254 rights in one sendmsg and rejects 255 with EINVAL;
// production still sizes against XNU's documented 512-FD receive ceiling.
const CURRENT_DARWIN_SENDABLE_RIGHTS: usize = 254;

#[test]
fn ctrunc_abort_probe() {
    if std::env::var_os(CTRUNC_CHILD).is_none() {
        return;
    }
    let (sender, receiver) = UnixStream::pair().expect("transport pair");
    let pairs: Vec<_> = (0..8)
        .map(|_| UnixStream::pair().expect("offered pair"))
        .collect();
    let descriptors: Vec<_> = pairs.iter().map(|(offered, _)| offered.as_fd()).collect();
    send_with_descriptors(&sender, &valid_frame(), &descriptors);
    crate::writer_endpoint_handoff::test_only_receive_with_tiny_control(&receiver);
    panic!("CTRUNC path returned instead of aborting");
}

#[test]
fn ancillary_truncation_is_fail_stop_sigabrt() {
    let current = std::env::current_exe().expect("current test executable");
    let output = Command::new(current)
        .args([
            "--exact",
            "writer_endpoint_handoff_tests::rejections::ctrunc_abort_probe",
        ])
        .env(CTRUNC_CHILD, "1")
        .output()
        .expect("run CTRUNC child");

    assert_eq!(output.status.signal(), Some(libc::SIGABRT), "{output:?}");
}

#[test]
fn current_darwin_maximum_rights_record_is_recoverably_rejected_and_closed() {
    let (sender, receiver) = UnixStream::pair().expect("transport pair");
    let pairs: Vec<_> = (0..CURRENT_DARWIN_SENDABLE_RIGHTS)
        .map(|_| UnixStream::pair().expect("offered pair"))
        .collect();
    let descriptors: Vec<_> = pairs.iter().map(|(offered, _)| offered.as_fd()).collect();
    send_with_descriptors(&sender, &valid_frame(), &descriptors);
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown writer");
    let peers: Vec<_> = pairs.into_iter().map(|(_, peer)| peer).collect();

    let Err(error) = crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET)
    else {
        panic!("maximum rights record was accepted");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error:?}");
    for peer in peers {
        assert_peer_closed(peer);
    }
}

#[test]
fn oversized_datagram_payload_is_rejected_as_truncated() {
    let (sender, receiver) = UnixDatagram::pair().expect("datagram pair");
    let (offered, peer) = UnixStream::pair().expect("offered endpoint");
    let mut oversized = valid_frame().to_vec();
    oversized.push(7);
    send_datagram_with_descriptor(&sender, &oversized, offered.as_fd());
    drop(offered);

    assert!(
        crate::writer_endpoint_handoff::test_only_receive_raw_segment(&receiver, RECEIVE_BUDGET)
            .is_err()
    );
    assert_peer_closed(peer);
}

#[test]
fn file_pipe_inet_unconnected_unix_and_datagram_fail_preflight() {
    let file = std::fs::File::open("/dev/null").expect("open null");
    assert!(crate::writer_endpoint_handoff::receive_for_test(&file, RECEIVE_BUDGET).is_err());

    let (pipe_reader, pipe_writer) = nix::unistd::pipe().expect("pipe");
    assert!(
        crate::writer_endpoint_handoff::receive_for_test(&pipe_reader, RECEIVE_BUDGET).is_err()
    );
    drop(pipe_writer);

    let listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("TCP listener");
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("TCP client");
    let (server, _) = listener.accept().expect("TCP accept");
    assert!(crate::writer_endpoint_handoff::receive_for_test(&client, RECEIVE_BUDGET).is_err());
    drop(server);

    let unconnected = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        nix::sys::socket::SockFlag::empty(),
        None,
    )
    .expect("unconnected Unix stream");
    assert!(
        crate::writer_endpoint_handoff::receive_for_test(&unconnected, RECEIVE_BUDGET).is_err()
    );

    let (_sender, receiver) = UnixDatagram::pair().expect("datagram pair");
    assert!(crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET).is_err());
}

#[test]
fn zero_channel_or_publication_key_is_rejected() {
    for range in [0..32, 96..128] {
        let (sender, receiver) = UnixStream::pair().expect("transport pair");
        let (offered, peer) = UnixStream::pair().expect("offered endpoint");
        let mut frame = valid_frame();
        frame[range].fill(0);
        send_with_descriptors(&sender, &frame, &[offered.as_fd()]);
        drop(offered);
        sender
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown writer");
        assert!(
            crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET).is_err()
        );
        assert_peer_closed(peer);
    }
}
