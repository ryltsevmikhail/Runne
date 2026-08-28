#[cfg(target_os = "linux")]
use std::io::IoSlice;
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use std::net::Shutdown;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd as _;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

#[cfg(target_os = "linux")]
#[test]
fn descriptor_receive_rejects_a_second_fd_after_the_first_frame_segment() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let (first, _) = UnixStream::pair().unwrap();
    let (second, _) = UnixStream::pair().unwrap();
    let frame = [0; 160];
    send_segment(&mut sender, &frame[..1], first.as_fd());
    send_segment(&mut sender, &frame[1..], second.as_fd());
    sender.shutdown(Shutdown::Write).unwrap();

    assert!(matches!(
        super::unix_descriptor::receive_descriptor::<160>(&mut receiver),
        Err(runne_platform_ports::provider_credential_broker::BrokerHandoffError::Rejected)
    ));
}

#[cfg(target_os = "linux")]
fn send_segment(transport: &mut UnixStream, frame: &[u8], descriptor: std::os::fd::BorrowedFd<'_>) {
    let descriptors = [descriptor];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    let sent = sendmsg(
        transport,
        &[IoSlice::new(frame)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .unwrap();
    assert_eq!(sent, frame.len());
}
