//! Unix SCM_RIGHTS fd transport (macOS/Linux): send/receive one
//! descriptor over an authenticated unix stream. The receiver MUST set
//! and verify `FD_CLOEXEC` immediately — Darwin does not preserve the
//! sender's `FD_CLOEXEC` through `SCM_RIGHTS`.

use crate::broker::error::BrokerError;
use rustix::fd::{BorrowedFd, OwnedFd};
use rustix::net::RecvAncillaryMessage;
use std::os::unix::net::UnixStream;

/// Sends one duplicated descriptor over the stream via `SCM_RIGHTS`.
pub fn send_one(socket: &UnixStream, fd: BorrowedFd<'_>) -> Result<(), BrokerError> {
    let data = [0u8; 1];
    let iov = [std::io::IoSlice::new(&data)];
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
    let message = rustix::net::SendAncillaryMessage::ScmRights(&[fd]);
    if !ancillary.push(message) {
        return Err(BrokerError::Transport("cmsg push failed".into()));
    }
    let sent = rustix::net::sendmsg(
        socket,
        &iov,
        &mut ancillary,
        rustix::net::SendFlags::empty(),
    )
    .map_err(|e| BrokerError::Transport(e.to_string()))?;
    if sent == 0 {
        return Err(BrokerError::Transport("fd not sent".into()));
    }
    Ok(())
}

/// Receives exactly one descriptor; sets and verifies `FD_CLOEXEC`
/// immediately (Darwin drops the sender's flag across `SCM_RIGHTS`).
/// Zero or multiple fds is a protocol violation; all received fds are
/// closed on every error path.
pub fn recv_one(socket: &UnixStream) -> Result<OwnedFd, BrokerError> {
    let mut data = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut data)];
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = rustix::net::RecvAncillaryBuffer::new(&mut space);
    let msg = rustix::net::recvmsg(
        socket,
        &mut iov,
        &mut ancillary,
        rustix::net::RecvFlags::empty(),
    )
    .map_err(|e| BrokerError::Transport(e.to_string()))?;
    if msg.bytes == 0 {
        return Err(BrokerError::Transport("peer closed".into()));
    }
    let mut received: Vec<OwnedFd> = Vec::new();
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = message {
            received.extend(fds);
        }
    }
    if received.len() != 1 {
        // Close every received descriptor on the error path.
        return Err(BrokerError::FdCountUnexpected);
    }
    let fd = received.remove(0);
    // Immediate CLOEXEC set + verify before any use.
    let flags = rustix::io::fcntl_getfd(&fd).map_err(|_| BrokerError::FdCloexecMissing)?;
    rustix::io::fcntl_setfd(&fd, flags | rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| BrokerError::FdCloexecMissing)?;
    let verified = rustix::io::fcntl_getfd(&fd).map_err(|_| BrokerError::FdCloexecMissing)?;
    if !verified.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(BrokerError::FdCloexecMissing);
    }
    Ok(fd)
}
