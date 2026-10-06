pub(super) use super::LinuxCommandError;
use super::child::stdio::CommandStdio;
use super::snapshot::SealedExecutableSnapshot;
use super::{child, gate, io::LinuxCommandOutputLimitsV1, policy};
#[path = "spec/argv.rs"]
mod argv;
#[path = "spec/executable.rs"]
mod executable;
use crate::process_managed_area::LinuxManagedArea;
use argv::encode_vectors;
use rustix::process::{Signal, pidfd_send_signal};
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};
#[path = "spec/containment.rs"]
mod containment;
pub use containment::LinuxCommandContainmentV1;

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
        child::spawn(child::SpawnSpec {
            exe: self.executable.file(),
            workspace: self.workspace,
            cwd: self.cwd,
            ruleset: Some(&ruleset),
            argv: &argv,
            env: &env,
            area,
            stdio: CommandStdio::discard()?,
            composite: None,
            network_none: false,
        })
    }

    /// Spawns through the same held-executable, Landlock, gate, and cgroup path
    /// with sealed preloaded stdin and bounded, explicitly polled output pipes.
    pub fn spawn_gated_with_io<'a>(
        &self,
        area: &'a LinuxManagedArea,
        input: &[u8],
        limits: LinuxCommandOutputLimitsV1,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        let (argv, env) = encode_vectors(&self.argv, &self.env)?;
        self.executable.validate_provenance()?;
        policy::validate_descriptors(self.executable.file(), self.workspace, self.cwd)?;
        let stdio = CommandStdio::bounded(input, limits)?;
        let ruleset = policy::build_ruleset(self.workspace, &self.executable)?;
        child::spawn(child::SpawnSpec {
            exe: self.executable.file(),
            workspace: self.workspace,
            cwd: self.cwd,
            ruleset: Some(&ruleset),
            argv: &argv,
            env: &env,
            area,
            stdio,
            composite: None,
            network_none: false,
        })
    }
}

/// Caller-owned unreaped gated child in the exact managed area.
pub struct GatedLinuxChild<'a> {
    pub(super) pid: i32,
    pub(super) pidfd: OwnedFd,
    pub(super) go: OwnedFd,
    pub(super) area: &'a LinuxManagedArea,
    pub(super) released: bool,
    pub(super) go_written: bool,
    pub(super) reaped: bool,
    pub(super) exit_code: Option<i32>,
    pub(super) output: Option<child::output::OutputCapture>,
}
impl GatedLinuxChild<'_> {
    /// PID is diagnostic only; signaling and ownership use the held pidfd.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    /// Reports whether the GO byte was written to this child's held gate.
    #[must_use]
    pub const fn was_released(&self) -> bool {
        self.go_written
    }

    /// Releases trusted gate only after the caller has durably admitted execution.
    /// Durable cancellation fencing is the caller’s responsibility.
    pub fn release(&mut self) -> Result<(), LinuxCommandError> {
        if self.go_written || self.released || self.reaped {
            return Err(LinuxCommandError::Unverified);
        }
        gate::write_byte(self.go.as_raw_fd(), b'G')?;
        self.go_written = true;
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
            self.poll_output()?;
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
            return self
                .exit_code
                .map(Some)
                .ok_or(LinuxCommandError::Unverified);
        }
        let mut status = 0;
        // SAFETY: status points to writable storage and pid is our unreaped child.
        let got = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if got == self.pid {
            self.reaped = true;
            let exit_code = decode_status(status)?;
            self.exit_code = Some(exit_code);
            return Ok(Some(exit_code));
        }
        if got == 0 {
            return Ok(None);
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            return Ok(None);
        }
        Err(LinuxCommandError::Unverified)
    }

    /// Nonblocking bounded drain of configured stdout/stderr, at most 8 KiB.
    /// Call alongside cancellation and deadline checks; pipe EOF is separate
    /// from leader exit and cgroup emptiness.
    pub fn poll_output(&mut self) -> Result<(), LinuxCommandError> {
        if let Some(output) = &mut self.output {
            output.poll()?;
        }
        Ok(())
    }

    /// Transfers bytes collected since the previous call. Truncation flags are
    /// sticky for the invocation; EOF and leader exit are independent proofs.
    pub fn take_output(&mut self) -> super::io::LinuxCommandOutputChunkV1 {
        self.output.as_mut().map_or_else(
            || super::io::LinuxCommandOutputChunkV1 {
                leader_exit_code: self.exit_code,
                ..Default::default()
            },
            |output| output.take(self.exit_code),
        )
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
        child::supervision::reap_bounded_or_defer(self.pid);
        self.reaped = true;
    }
}
