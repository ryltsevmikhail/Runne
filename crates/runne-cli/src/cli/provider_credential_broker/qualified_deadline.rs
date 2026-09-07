use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

pub(super) const BUDGET: Duration = Duration::from_secs(5);

#[cfg(test)]
pub(super) struct QualifiedBrokerControl<C> {
    inner: C,
    deadline: Instant,
}

#[cfg(test)]
impl<C> QualifiedBrokerControl<C> {
    pub(super) fn new(inner: C) -> Self {
        Self::with_budget(inner, BUDGET)
    }

    fn with_budget(inner: C, budget: Duration) -> Self {
        let deadline = Instant::now()
            .checked_add(budget)
            .expect("qualified exchange deadline representable");
        Self { inner, deadline }
    }

    pub(super) fn finish(self) -> io::Result<C> {
        self.ensure_remaining()?;
        Ok(self.inner)
    }

    fn ensure_remaining(&self) -> io::Result<()> {
        remaining(self.deadline).map(|_| ())
    }
}

#[cfg(test)]
impl<C: Read> Read for QualifiedBrokerControl<C> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.ensure_remaining()?;
        let read = self.inner.read(bytes)?;
        self.ensure_remaining()?;
        Ok(read)
    }
}

#[cfg(test)]
impl<C: Write> Write for QualifiedBrokerControl<C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.ensure_remaining()?;
        let written = self.inner.write(bytes)?;
        self.ensure_remaining()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ensure_remaining()?;
        self.inner.flush()?;
        self.ensure_remaining()
    }
}

#[cfg(target_os = "macos")]
pub(super) struct QualifiedSocketControl {
    inner: std::os::unix::net::UnixStream,
    deadline: Instant,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

#[cfg(target_os = "macos")]
impl QualifiedSocketControl {
    pub(super) fn new(inner: std::os::unix::net::UnixStream) -> io::Result<Self> {
        Self::with_budget(inner, BUDGET)
    }

    fn with_budget(inner: std::os::unix::net::UnixStream, budget: Duration) -> io::Result<Self> {
        let read_timeout = inner.read_timeout()?;
        let write_timeout = inner.write_timeout()?;
        let deadline = Instant::now()
            .checked_add(budget)
            .expect("qualified exchange deadline representable");
        Ok(Self {
            inner,
            deadline,
            read_timeout,
            write_timeout,
        })
    }

    pub(super) fn finish(self) -> io::Result<std::os::unix::net::UnixStream> {
        remaining(self.deadline)?;
        self.inner.set_read_timeout(self.read_timeout)?;
        self.inner.set_write_timeout(self.write_timeout)?;
        Ok(self.inner)
    }

    fn prepare_read(&self) -> io::Result<()> {
        self.inner.set_read_timeout(Some(remaining(self.deadline)?))
    }

    fn prepare_write(&self) -> io::Result<()> {
        self.inner
            .set_write_timeout(Some(remaining(self.deadline)?))
    }

    fn check(&self) -> io::Result<()> {
        remaining(self.deadline).map(|_| ())
    }
}

#[cfg(target_os = "macos")]
impl Read for QualifiedSocketControl {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.prepare_read()?;
        let read = self.inner.read(bytes)?;
        self.check()?;
        Ok(read)
    }
}

#[cfg(target_os = "macos")]
impl Write for QualifiedSocketControl {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.prepare_write()?;
        let written = self.inner.write(bytes)?;
        self.check()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.prepare_write()?;
        self.inner.flush()?;
        self.check()
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "qualified exchange timed out"))
}

#[cfg(test)]
#[cfg(target_os = "macos")]
#[path = "qualified_deadline_tests.rs"]
mod tests;
