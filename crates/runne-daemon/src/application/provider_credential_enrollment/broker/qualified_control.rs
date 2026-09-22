use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub(super) const BUDGET: Duration = Duration::from_secs(5);
const ORDINARY_TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct QualifiedControl<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl<'a> QualifiedControl<'a> {
    pub(super) fn new(stream: &'a mut UnixStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }

    pub(super) fn check_deadline(deadline: Instant) -> io::Result<()> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(|_| ())
            .ok_or_else(timeout)
    }

    pub(super) fn ensure_remaining(&self) -> io::Result<()> {
        Self::check_deadline(self.deadline)
    }

    fn read_with_remaining(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.ensure_remaining()?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout)?;
        self.stream.set_read_timeout(Some(remaining))?;
        let result = self.stream.read(bytes);
        let restored = self
            .stream
            .set_read_timeout(Some(ORDINARY_TRANSPORT_TIMEOUT));
        let read = result?;
        restored?;
        self.ensure_remaining()?;
        Ok(read)
    }

    fn write_with_remaining(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.ensure_remaining()?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout)?;
        self.stream.set_write_timeout(Some(remaining))?;
        let result = self.stream.write(bytes);
        let restored = self
            .stream
            .set_write_timeout(Some(ORDINARY_TRANSPORT_TIMEOUT));
        let written = result?;
        restored?;
        self.ensure_remaining()?;
        Ok(written)
    }
}

impl Read for QualifiedControl<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.read_with_remaining(bytes)
    }
}

impl Write for QualifiedControl<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_with_remaining(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ensure_remaining()?;
        self.stream.flush()?;
        self.ensure_remaining()
    }
}

fn timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "qualified exchange timed out")
}
