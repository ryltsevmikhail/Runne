//! Worker-channel transport: authenticated frame + one ancillary fd
//! (SCM_RIGHTS) per load. The trait is shared by the host client and
//! the worker process so both ends run the same wire rules; the Unix
//! implementation follows the broker's CLOEXEC discipline (Darwin drops
//! the sender's flag across SCM_RIGHTS, so the receiver sets+verifies).

use crate::error::ProtocolError;
use rustix::fd::{BorrowedFd, OwnedFd};
use rustix::net::RecvAncillaryMessage;
use std::os::unix::net::UnixStream;

pub trait WorkerWire {
    /// Sends one encoded session frame.
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), ProtocolError>;
    /// Receives the next encoded session frame.
    fn recv_frame(&mut self) -> Result<Vec<u8>, ProtocolError>;
    /// Sends exactly one descriptor (load path only).
    fn send_fd(&mut self, fd: BorrowedFd<'_>) -> Result<(), ProtocolError>;
    /// Receives exactly one descriptor; zero or several is fatal.
    fn recv_fd(&mut self) -> Result<OwnedFd, ProtocolError>;
}

const MAX_WIRE_FRAME: usize = 1024 * 1024;

/// Unix-stream wire. Frames carry a 4-byte big-endian length prefix;
/// fd transfers are separate one-byte SCM_RIGHTS messages.
pub struct UnixWorkerWire {
    stream: UnixStream,
}

impl UnixWorkerWire {
    pub fn new(stream: UnixStream) -> Self {
        Self { stream }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ProtocolError> {
        let mut done = 0;
        while done < buf.len() {
            let n = std::io::Read::read(&mut self.stream, &mut buf[done..])
                .map_err(|_| ProtocolError::Malformed)?;
            if n == 0 {
                return Err(ProtocolError::Malformed);
            }
            done += n;
        }
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), ProtocolError> {
        std::io::Write::write_all(&mut self.stream, buf).map_err(|_| ProtocolError::Malformed)
    }
}

impl WorkerWire for UnixWorkerWire {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), ProtocolError> {
        if frame.len() > MAX_WIRE_FRAME {
            return Err(ProtocolError::Malformed);
        }
        self.write_all(&(frame.len() as u32).to_be_bytes())?;
        self.write_all(frame)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let mut len = [0u8; 4];
        self.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_WIRE_FRAME {
            return Err(ProtocolError::Malformed);
        }
        let mut frame = vec![0u8; len];
        self.read_exact(&mut frame)?;
        Ok(frame)
    }

    fn send_fd(&mut self, fd: BorrowedFd<'_>) -> Result<(), ProtocolError> {
        let data = [0u8; 1];
        let iov = [std::io::IoSlice::new(&data)];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
        let message = rustix::net::SendAncillaryMessage::ScmRights(&[fd]);
        if !ancillary.push(message) {
            return Err(ProtocolError::Malformed);
        }
        let sent = rustix::net::sendmsg(
            &self.stream,
            &iov,
            &mut ancillary,
            rustix::net::SendFlags::empty(),
        )
        .map_err(|_| ProtocolError::Malformed)?;
        if sent == 0 {
            return Err(ProtocolError::Malformed);
        }
        Ok(())
    }

    fn recv_fd(&mut self) -> Result<OwnedFd, ProtocolError> {
        let mut data = [0u8; 1];
        let mut iov = [std::io::IoSliceMut::new(&mut data)];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = rustix::net::RecvAncillaryBuffer::new(&mut space);
        let msg = rustix::net::recvmsg(
            &self.stream,
            &mut iov,
            &mut ancillary,
            rustix::net::RecvFlags::empty(),
        )
        .map_err(|_| ProtocolError::Malformed)?;
        if msg.bytes == 0 {
            return Err(ProtocolError::Malformed);
        }
        let mut received: Vec<OwnedFd> = Vec::new();
        for message in ancillary.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = message {
                received.extend(fds);
            }
        }
        if received.len() != 1 {
            return Err(ProtocolError::Malformed);
        }
        let fd = received.remove(0);
        // Immediate CLOEXEC set + verify before any use.
        let flags = rustix::io::fcntl_getfd(&fd).map_err(|_| ProtocolError::Malformed)?;
        rustix::io::fcntl_setfd(&fd, flags | rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| ProtocolError::Malformed)?;
        let verified = rustix::io::fcntl_getfd(&fd).map_err(|_| ProtocolError::Malformed)?;
        if !verified.contains(rustix::io::FdFlags::CLOEXEC) {
            return Err(ProtocolError::Malformed);
        }
        Ok(fd)
    }
}
