#![cfg(test)]

use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

use super::support::{FRAME_BYTES, valid_frame};
use super::support::{RECEIVE_BUDGET, assert_peer_closed, receive_exact, send_with_descriptors};

#[test]
fn exact_frame_retains_fields_digest_and_cloexec_descriptor() {
    let frame = valid_frame();
    let handoff = receive_exact(&frame);

    assert_eq!(handoff.test_only_frame(), &frame);
    assert_eq!(handoff.test_only_channel_binding(), &[1; 32]);
    assert_eq!(handoff.test_only_publication_public_key(), &[2; 32]);
    assert_eq!(
        handoff.test_only_digest(),
        &[
            0x2b, 0x6c, 0xb7, 0x96, 0x29, 0x1f, 0x63, 0xed, 0x3a, 0x51, 0xbb, 0x24, 0xd0, 0xdc,
            0x27, 0x58, 0x12, 0x4c, 0x11, 0x78, 0x5f, 0x92, 0x98, 0x57, 0x10, 0xf6, 0x7e, 0xcb,
            0xbd, 0x11, 0x59, 0x2f,
        ]
    );
    assert!(handoff.test_only_has_cloexec());
}

#[test]
fn every_frame_byte_contributes_to_the_digest() {
    let baseline = receive_exact(&valid_frame()).test_only_digest().to_owned();
    for position in 0..FRAME_BYTES {
        let mut mutated = valid_frame();
        mutated[position] ^= 0x80;
        let digest = receive_exact(&mutated).test_only_digest().to_owned();
        assert_ne!(digest, baseline, "digest ignored byte {position}");
    }
}

#[test]
fn dropping_success_closes_the_retained_descriptor() {
    let (sender, receiver) = UnixStream::pair().expect("transport pair");
    let (offered, mut peer) = UnixStream::pair().expect("offered endpoint");
    send_with_descriptors(&sender, &valid_frame(), &[offered.as_fd()]);
    drop(offered);
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown writer");

    let handoff = crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET)
        .expect("handoff");
    peer.write_all(&[1]).expect("retained descriptor is live");
    drop(handoff);
    assert_peer_closed(peer);
}

#[test]
fn exact_queued_record_survives_both_transfer_half_closes() {
    let (sender, receiver) = UnixStream::pair().expect("transport pair");
    let (offered, _) = UnixStream::pair().expect("offered endpoint");
    receiver
        .shutdown(std::net::Shutdown::Write)
        .expect("finish challenge direction");
    send_with_descriptors(&sender, &valid_frame(), &[offered.as_fd()]);
    sender
        .shutdown(std::net::Shutdown::Write)
        .expect("finish response direction");

    crate::writer_endpoint_handoff::receive_for_test(&receiver, RECEIVE_BUDGET)
        .expect("queued exact handoff");
}
