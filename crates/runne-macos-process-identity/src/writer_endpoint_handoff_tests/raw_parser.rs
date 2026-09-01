#![cfg(test)]

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use super::support::assert_peer_closed;

#[test]
fn production_control_buffer_covers_the_xnu_rights_ceiling() {
    assert!(crate::writer_endpoint_handoff::test_only_control_buffer_covers_xnu_ceiling());
}

#[test]
fn unknown_cmsg_rejection_still_adopts_and_closes_visible_rights() {
    let (offered, peer) = UnixStream::pair().expect("offered endpoint");
    let descriptor: OwnedFd = offered.into();

    assert!(
        crate::writer_endpoint_handoff::test_only_parse_unknown_then_rights(descriptor).is_err()
    );
    assert_peer_closed(peer);
}

#[test]
fn malformed_cursor_rejection_still_adopts_and_closes_visible_rights() {
    let (offered, peer) = UnixStream::pair().expect("offered endpoint");
    let descriptor: OwnedFd = offered.into();

    assert!(
        crate::writer_endpoint_handoff::test_only_parse_rights_then_malformed(descriptor).is_err()
    );
    assert_peer_closed(peer);
}

#[test]
fn negative_duplicate_partial_and_trailing_control_are_rejected_after_adoption() {
    let cases: [fn(OwnedFd) -> std::io::Result<()>; 4] = [
        crate::writer_endpoint_handoff::test_only_parse_negative_then_rights,
        crate::writer_endpoint_handoff::test_only_parse_duplicate_rights,
        crate::writer_endpoint_handoff::test_only_parse_partial_rights,
        crate::writer_endpoint_handoff::test_only_parse_rights_then_trailing,
    ];
    for parse in cases {
        let (offered, peer) = UnixStream::pair().expect("offered endpoint");
        assert!(parse(offered.into()).is_err());
        assert_peer_closed(peer);
    }
}
