use std::io;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{SockType, UnixAddr, getpeername, getsockname, getsockopt, sockopt};

use super::raw_recvmsg_macos::{self, RawSegment};

pub(super) const FRAME_BYTES: usize = 160;

pub(super) struct ReceivedHandoff {
    pub(super) control: OwnedFd,
    pub(super) frame: [u8; FRAME_BYTES],
}

pub(super) fn receive(transport: &impl AsFd, budget: Duration) -> io::Result<ReceivedHandoff> {
    let started = Instant::now();
    let deadline = started.checked_add(budget).ok_or_else(timed_out)?;
    require_connected_unix_stream(transport)?;

    let mut frame = [0; FRAME_BYTES];
    let mut descriptors = Vec::new();
    let mut offset = 0;
    while offset < frame.len() {
        let segment = receive_segment(transport, &mut frame[offset..], deadline)?;
        reject_truncated(&segment)?;
        if segment.bytes == 0 {
            return Err(invalid_record());
        }
        offset += segment.bytes;
        descriptors.extend(segment.descriptors);
        if descriptors.len() > 1 {
            return Err(invalid_record());
        }
    }

    let before_probe = descriptors.len();
    let mut trailing = [0; 1];
    let probe = receive_segment(transport, &mut trailing, deadline)?;
    reject_truncated(&probe)?;
    descriptors.extend(probe.descriptors);
    if probe.bytes != 0 || descriptors.len() != before_probe {
        return Err(invalid_record());
    }
    let control = exact_descriptor(descriptors)?;
    if frame[..32] == [0; 32] || frame[96..128] == [0; 32] {
        return Err(invalid_record());
    }
    Ok(ReceivedHandoff { control, frame })
}

fn receive_segment(
    transport: &impl AsFd,
    bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<RawSegment> {
    loop {
        wait_readable(transport, deadline)?;
        match raw_recvmsg_macos::receive(transport.as_fd(), bytes) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            result => return result,
        }
    }
}

fn wait_readable(transport: &impl AsFd, deadline: Instant) -> io::Result<()> {
    loop {
        let timeout = remaining_timeout(deadline)?;
        let mut descriptors = [PollFd::new(transport.as_fd(), PollFlags::POLLIN)];
        match poll(&mut descriptors, timeout) {
            Ok(0) => return Err(timed_out()),
            Ok(_) => {
                let events = descriptors[0].revents().ok_or_else(invalid_record)?;
                if events.intersects(PollFlags::POLLNVAL | PollFlags::POLLERR) {
                    return Err(invalid_record());
                }
                if events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                    return Ok(());
                }
            }
            Err(Errno::EINTR) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

fn remaining_timeout(deadline: Instant) -> io::Result<PollTimeout> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(timed_out)?;
    if remaining.is_zero() {
        return Err(timed_out());
    }
    let millis = remaining.as_nanos().div_ceil(1_000_000);
    PollTimeout::try_from(millis).map_err(io::Error::other)
}

fn require_connected_unix_stream(transport: &impl AsFd) -> io::Result<()> {
    if getsockopt(transport, sockopt::SockType).map_err(io::Error::from)? != SockType::Stream {
        return Err(invalid_record());
    }
    let raw = transport.as_fd().as_raw_fd();
    getsockname::<UnixAddr>(raw).map_err(|_| invalid_record())?;
    getpeername::<UnixAddr>(raw).map_err(|_| invalid_record())?;
    Ok(())
}

fn exact_descriptor(mut descriptors: Vec<OwnedFd>) -> io::Result<OwnedFd> {
    (descriptors.len() == 1)
        .then(|| descriptors.pop())
        .flatten()
        .ok_or_else(invalid_record)
}

fn reject_truncated(segment: &RawSegment) -> io::Result<()> {
    (!segment.truncated)
        .then_some(())
        .ok_or_else(invalid_record)
}

fn invalid_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid writer endpoint handoff",
    )
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "writer endpoint handoff timed out")
}

#[cfg(test)]
pub(super) fn test_receive_raw_segment(transport: &impl AsFd, budget: Duration) -> io::Result<()> {
    let deadline = Instant::now().checked_add(budget).ok_or_else(timed_out)?;
    let segment = receive_segment(transport, &mut [0; FRAME_BYTES], deadline)?;
    reject_truncated(&segment)
}

#[cfg(test)]
pub(super) fn test_receive_with_tiny_control(transport: &impl AsFd) {
    let mut bytes = [0; FRAME_BYTES];
    raw_recvmsg_macos::test_receive_with_tiny_control(transport.as_fd(), &mut bytes);
}
