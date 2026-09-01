use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{MsgFlags, recv};

pub(super) struct DeadlineReader<'a> {
    stream: BorrowedFd<'a>,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    pub(super) fn new(stream: &'a impl std::os::fd::AsFd, budget: Duration) -> io::Result<Self> {
        let deadline = Instant::now().checked_add(budget).ok_or_else(timed_out)?;
        Ok(Self {
            stream: stream.as_fd(),
            deadline,
        })
    }

    pub(super) fn reject_queued_input(&self) -> io::Result<()> {
        loop {
            let _ = remaining_timeout(self.deadline)?;
            let mut byte = [0_u8; 1];
            match recv(
                self.stream.as_raw_fd(),
                &mut byte,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_PEEK,
            ) {
                Err(Errno::EAGAIN) => return Ok(()),
                Err(Errno::EINTR) => {}
                Ok(_) | Err(_) => return Err(invalid_record()),
            }
        }
    }
}

impl io::Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            wait_readable(self.stream, self.deadline)?;
            let _ = remaining_timeout(self.deadline)?;
            match recv(self.stream.as_raw_fd(), buffer, MsgFlags::MSG_DONTWAIT) {
                Err(Errno::EAGAIN | Errno::EINTR) => {}
                Ok(0) => return Err(invalid_record()),
                Ok(read) => return Ok(read),
                Err(error) => return Err(io::Error::from(error)),
            }
        }
    }
}

fn wait_readable(stream: BorrowedFd<'_>, deadline: Instant) -> io::Result<()> {
    loop {
        let mut descriptors = [PollFd::new(stream, PollFlags::POLLIN)];
        match poll(&mut descriptors, remaining_timeout(deadline)?) {
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
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(timed_out)?;
    PollTimeout::try_from(remaining.as_nanos().div_ceil(1_000_000)).map_err(io::Error::other)
}

fn invalid_record() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid bootstrap transcript")
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "bootstrap transcript timed out")
}
