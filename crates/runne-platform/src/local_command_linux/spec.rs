use super::snapshot::SealedExecutableSnapshot;
use super::{child, gate, policy};
use crate::process_managed_area::{LinuxManagedArea, ManagedAreaError};
use rustix::process::{Signal, pidfd_send_signal};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

/// Closed launch failures. Native path and OS error details are not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinuxCommandError {
    /// Required kernel restrictions or delegated cgroup support are unavailable.
    #[error("protected Linux command execution unavailable")]
    Unavailable,
    /// The structured command or held descriptor set is invalid.
    #[error("structured Linux command is invalid")]
    Invalid,
    /// Gate, exact-area attach, or child-state proof failed.
    #[error("Linux command gate is unverified")]
    Unverified,
    /// Child wait exceeded the caller's bounded policy.
    #[error("Linux command wait timed out")]
    Timeout,
    /// Exact managed-area lifecycle operation failed.
    #[error("managed process area operation failed")]
    Area,
}
impl From<ManagedAreaError> for LinuxCommandError {
    fn from(_: ManagedAreaError) -> Self {
        Self::Area
    }
}

/// Structured argv/environment plus caller-opened executable, workspace, and cwd.
/// The caller must already have approved this exact command and canonical workspace.
/// This low-level primitive does not create approvals or persist launch intent.
pub struct LinuxCommandSpec<'a> {
    /// Held filesystem executable or sealed approved bytes; scripts are unsupported.
    pub executable: LinuxCommandExecutable<'a>,
    /// Canonical workspace root descriptor; cgroup2 mountpoints are rejected.
    pub workspace: &'a File,
    /// Held working-directory descriptor proven beneath `workspace`.
    pub cwd: &'a File,
    /// Explicit argument vector; this API never parses shell syntax.
    pub argv: Vec<OsString>,
    /// Explicit environment entries.
    pub env: Vec<(OsString, OsString)>,
}

/// Typed executable provenance. A sealed snapshot is the only anonymous-file
/// case allowed to omit a Landlock PATH_BENEATH rule.
pub enum LinuxCommandExecutable<'a> {
    /// Broker-held executable residing in the protected filesystem.
    HeldFile(&'a File),
    /// Opaque snapshot created and sealed by this crate from a held executable.
    SealedSnapshot(&'a SealedExecutableSnapshot),
}

impl LinuxCommandExecutable<'_> {
    pub(super) fn file(&self) -> &File {
        match self {
            Self::HeldFile(file) => file,
            Self::SealedSnapshot(snapshot) => snapshot.file(),
        }
    }
    pub(super) fn is_sealed_snapshot(&self) -> bool {
        matches!(self, Self::SealedSnapshot(_))
    }
    fn validate_provenance(&self) -> Result<(), LinuxCommandError> {
        if let Self::SealedSnapshot(snapshot) = self {
            snapshot.validate_seals()?;
        }
        Ok(())
    }
}

impl LinuxCommandSpec<'_> {
    /// Checks all local kernel gate and descriptor requirements without forking.
    /// Call before claiming a TaskRun or creating an approval.
    pub fn preflight(&self) -> Result<(), LinuxCommandError> {
        let _ = encode_vectors(&self.argv, &self.env)?;
        self.executable.validate_provenance()?;
        policy::validate_descriptors(self.executable.file(), self.workspace, self.cwd)?;
        drop(policy::build_ruleset(self.workspace, &self.executable)?);
        Ok(())
    }

    /// Forks a trusted gate child, applies Landlock before stop, and attaches it
    /// to an empty exact area. User code cannot run until `release` is called.
    /// Caller must ensure no generic child reaper competes for this direct child;
    /// ignored or auto-reaped SIGCHLD dispositions are rejected. Caught handlers
    /// are safe only when they do not reap children.
    pub fn spawn_gated<'a>(
        &self,
        area: &'a LinuxManagedArea,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        let (argv, env) = encode_vectors(&self.argv, &self.env)?;
        self.executable.validate_provenance()?;
        policy::validate_descriptors(self.executable.file(), self.workspace, self.cwd)?;
        let ruleset = policy::build_ruleset(self.workspace, &self.executable)?;
        child::spawn(
            self.executable.file(),
            self.workspace,
            self.cwd,
            &ruleset,
            &argv,
            &env,
            area,
        )
    }
}

fn encode_vectors(
    argv: &[OsString],
    env: &[(OsString, OsString)],
) -> Result<(Vec<CString>, Vec<CString>), LinuxCommandError> {
    if argv.is_empty() || argv.len() > 256 || env.len() > 256 {
        return Err(LinuxCommandError::Invalid);
    }
    let mut args = Vec::with_capacity(argv.len());
    for item in argv {
        let value = CString::new(item.as_bytes()).map_err(|_| LinuxCommandError::Invalid)?;
        if value.as_bytes().len() > 16 * 1024 {
            return Err(LinuxCommandError::Invalid);
        }
        args.push(value);
    }
    let mut vars = Vec::with_capacity(env.len());
    for (key, value) in env {
        if key.is_empty() || key.as_bytes().contains(&b'=') {
            return Err(LinuxCommandError::Invalid);
        }
        let mut bytes = key.as_bytes().to_vec();
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_bytes());
        let value = CString::new(bytes).map_err(|_| LinuxCommandError::Invalid)?;
        if value.as_bytes().len() > 16 * 1024 {
            return Err(LinuxCommandError::Invalid);
        }
        vars.push(value);
    }
    if args
        .iter()
        .chain(vars.iter())
        .map(|x| x.as_bytes().len())
        .sum::<usize>()
        > 128 * 1024
    {
        return Err(LinuxCommandError::Invalid);
    }
    Ok((args, vars))
}

/// Caller-owned unreaped gated child in the exact managed area.
pub struct GatedLinuxChild<'a> {
    pub(super) pid: i32,
    pub(super) pidfd: OwnedFd,
    pub(super) go: OwnedFd,
    pub(super) area: &'a LinuxManagedArea,
    pub(super) released: bool,
    pub(super) reaped: bool,
}
impl GatedLinuxChild<'_> {
    /// PID is diagnostic only; signaling and ownership use the held pidfd.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    /// Releases trusted gate only after the caller has durably admitted execution.
    /// Durable cancellation fencing is the caller’s responsibility.
    pub fn release(&mut self) -> Result<(), LinuxCommandError> {
        if self.released || self.reaped {
            return Err(LinuxCommandError::Unverified);
        }
        gate::write_byte(self.go.as_raw_fd(), b'G')?;
        pidfd_send_signal(&self.pidfd, Signal::CONT).map_err(|_| LinuxCommandError::Unverified)?;
        self.released = true;
        Ok(())
    }

    /// Cancels the complete exact cgroup area, then reaps the owned leader.
    pub fn cancel(mut self, grace: Duration) -> Result<(), LinuxCommandError> {
        self.area.terminate(grace)?;
        self.reap(Duration::from_secs(3))?;
        Ok(())
    }

    /// Waits for the direct command leader. Area emptiness remains a separate proof.
    pub fn wait(mut self, timeout: Duration) -> Result<i32, LinuxCommandError> {
        if timeout > Duration::from_secs(3600) {
            return Err(LinuxCommandError::Invalid);
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(LinuxCommandError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Polls the direct command leader without relinquishing this child handle.
    /// The caller must still prove that the complete managed area is empty.
    pub fn try_wait(&mut self) -> Result<Option<i32>, LinuxCommandError> {
        if self.reaped {
            return Err(LinuxCommandError::Unverified);
        }
        let mut status = 0;
        // SAFETY: status points to writable storage and pid is our unreaped child.
        let got = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if got == self.pid {
            self.reaped = true;
            return Ok(Some(decode_status(status)?));
        }
        if got == 0 {
            return Ok(None);
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            return Ok(None);
        }
        Err(LinuxCommandError::Unverified)
    }

    /// Sends TERM to the exact area and escalates through cgroup.kill on timeout.
    pub fn terminate_area(&self, grace: Duration) -> Result<(), LinuxCommandError> {
        self.area.terminate(grace).map_err(Into::into)
    }

    /// Reaps the direct command leader after a separately proven area stop.
    pub fn reap_after_stop(&mut self, timeout: Duration) -> Result<(), LinuxCommandError> {
        if self.reaped {
            return Ok(());
        }
        let _ = self.reap(timeout)?;
        Ok(())
    }

    fn reap(&mut self, timeout: Duration) -> Result<i32, LinuxCommandError> {
        if self.reaped || timeout > Duration::from_secs(3600) {
            return Err(LinuxCommandError::Invalid);
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(LinuxCommandError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
fn decode_status(status: i32) -> Result<i32, LinuxCommandError> {
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Err(LinuxCommandError::Unverified)
    }
}
impl Drop for GatedLinuxChild<'_> {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if self.released {
            if self.area.terminate(Duration::ZERO).is_err() {
                let _ = pidfd_send_signal(&self.pidfd, Signal::KILL);
            }
        } else {
            let _ = pidfd_send_signal(&self.pidfd, Signal::KILL);
        }
        child::reap_bounded_or_defer(self.pid);
        self.reaped = true;
    }
}
