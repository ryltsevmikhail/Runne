use std::io::IoSlice;
#[cfg(target_os = "linux")]
use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
#[cfg(target_os = "linux")]
use rustix::io::{FdFlags, fcntl_getfd};
#[cfg(target_os = "linux")]
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

pub(super) fn send_descriptor<const FRAME_SIZE: usize>(
    transport: &mut UnixStream,
    endpoint: &UnixStream,
    frame: &[u8; FRAME_SIZE],
) -> Result<(), BrokerHandoffError> {
    let descriptors = [endpoint.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(BrokerHandoffError::Unavailable);
    }
    let sent = sendmsg(
        transport,
        &[IoSlice::new(frame)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(|_| BrokerHandoffError::Unavailable)?;
    (sent == frame.len())
        .then_some(())
        .ok_or(BrokerHandoffError::Unavailable)
}

#[cfg(target_os = "linux")]
pub(super) fn receive_descriptor<const FRAME_SIZE: usize>(
    transport: &mut UnixStream,
) -> Result<([u8; FRAME_SIZE], OwnedFd), BrokerHandoffError> {
    let mut frame = [0; FRAME_SIZE];
    let mut descriptors = Vec::new();
    let mut offset = 0;
    while offset < frame.len() {
        let received = receive_segment(transport, &mut frame[offset..], &mut descriptors)?;
        if received == 0 {
            return Err(BrokerHandoffError::Rejected);
        }
        offset += received;
    }
    require_ancillary_aware_eof(transport, &mut descriptors)?;
    let descriptor = one_descriptor(descriptors)?;
    let flags = fcntl_getfd(&descriptor).map_err(|_| BrokerHandoffError::Unavailable)?;
    if !flags.contains(FdFlags::CLOEXEC) {
        return Err(BrokerHandoffError::Unavailable);
    }
    Ok((frame, descriptor))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn receive_descriptor<const FRAME_SIZE: usize>(
    _transport: &mut UnixStream,
) -> Result<([u8; FRAME_SIZE], OwnedFd), BrokerHandoffError> {
    Err(BrokerHandoffError::Unavailable)
}

#[cfg(target_os = "linux")]
fn receive_segment(
    transport: &mut UnixStream,
    bytes: &mut [u8],
    descriptors: &mut Vec<OwnedFd>,
) -> Result<usize, BrokerHandoffError> {
    let mut iov = [IoSliceMut::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        &mut *transport,
        &mut iov,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| BrokerHandoffError::Unavailable)?;
    if received
        .flags
        .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
    {
        return Err(BrokerHandoffError::Rejected);
    }
    append_descriptors(&mut ancillary, descriptors)?;
    Ok(received.bytes)
}

#[cfg(target_os = "linux")]
fn require_ancillary_aware_eof(
    transport: &mut UnixStream,
    descriptors: &mut Vec<OwnedFd>,
) -> Result<(), BrokerHandoffError> {
    let count = descriptors.len();
    let mut trailing = [0; 1];
    let received = receive_segment(transport, &mut trailing, descriptors)?;
    (received == 0 && descriptors.len() == count)
        .then_some(())
        .ok_or(BrokerHandoffError::Rejected)
}

#[cfg(target_os = "linux")]
fn append_descriptors(
    ancillary: &mut RecvAncillaryBuffer<'_>,
    descriptors: &mut Vec<OwnedFd>,
) -> Result<(), BrokerHandoffError> {
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = message {
            descriptors.extend(rights);
        } else {
            return Err(BrokerHandoffError::Rejected);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn one_descriptor(mut descriptors: Vec<OwnedFd>) -> Result<OwnedFd, BrokerHandoffError> {
    (descriptors.len() == 1)
        .then(|| descriptors.pop())
        .flatten()
        .ok_or(BrokerHandoffError::Rejected)
}
