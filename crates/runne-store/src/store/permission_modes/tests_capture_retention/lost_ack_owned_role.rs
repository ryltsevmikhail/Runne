//! Draft guest-only direct-child ownership; no inferred-PID collection.
use super::clock::Deadline;
use std::{io, process::{Child, ExitStatus}, time::Duration};

pub(super) struct OwnedRole {
    association: std::sync::Arc<()>,
    child: Child,
    status: Option<ExitStatus>,
    deadline: Deadline,
}
impl OwnedRole {
    // Caller transfers the actual freshly spawned handle, not a numeric PID.
    pub(super) fn from_child(child: Child, deadline: Deadline) -> Self {
        Self { child, status: None, deadline, association: std::sync::Arc::new(()) }
    }
    pub(super) fn association(&self) -> &std::sync::Arc<()> { &self.association }
    pub(super) fn id(&self) -> u32 { self.child.id() }
    pub(super) fn deadline(&self) -> Deadline { self.deadline }
    pub(super) fn live(&mut self) -> io::Result<()> {
        self.deadline.try_remaining().map_err(|_| io::ErrorKind::TimedOut)?;
        if self.status.is_none() { self.status = self.child.try_wait()?; }
        if self.status.is_some() { return Err(io::ErrorKind::InvalidData.into()); }
        Ok(())
    }
    pub(super) fn collect(&mut self) -> io::Result<ExitStatus> {
        loop {
            let left = self.deadline.try_remaining().map_err(|_| io::ErrorKind::TimedOut)?;
            if let Some(status) = self.status { return Ok(status); }
            if let Some(status) = self.child.try_wait()? {
                self.status = Some(status);
                self.deadline.try_remaining().map_err(|_| io::ErrorKind::TimedOut)?;
                return Ok(status);
            }
            std::thread::sleep(left.min(Duration::from_millis(1)));
        }
    }
    pub(super) fn collected_abort(&self) -> bool {
        use std::os::unix::process::ExitStatusExt;
        self.status.is_some_and(|status| status.signal() == Some(6) && status.code().is_none())
    }
}
impl Drop for OwnedRole {
    fn drop(&mut self) {
        if self.status.is_some() { return; }
        while let Ok(left) = self.deadline.try_remaining() {
            match self.child.try_wait() {
                Ok(Some(status)) => { self.status = Some(status); return; },
                Ok(None) => { let _ = self.child.kill(); },
                Err(_) => break,
            }
            std::thread::sleep(left.min(Duration::from_millis(1)));
        }
        // Failure cannot be reported as successful cleanup; guest collector/init
        // remains separately responsible for adopted descendants and STOP.
        std::hint::black_box(&self.child);
        std::process::abort();
    }
}
