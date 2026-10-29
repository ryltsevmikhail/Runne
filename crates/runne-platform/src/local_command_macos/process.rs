//! Bounded macOS process-area child with group termination and emptiness proof.
#![allow(unsafe_code)]

use super::area::{MacOsAreaIdentity, MacOsManagedArea, VerifiedEmptyMacOsArea};
use super::error::MacOsCommandError as CommandError;
use super::exit::{LinuxLeaderExitKindV1, LinuxLeaderExitObservationV1};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const MAX_OUTPUT_BYTES: usize = 8 * 1024;

/// Exact command request for the macOS adapter.
pub struct MacOsCommandSpec<'a> {
    /// Absolute executable path.
    pub executable: &'a Path,
    /// Arguments excluding `argv[0]`.
    pub arguments: &'a [String],
    /// Working directory.
    pub cwd: &'a Path,
    /// Cleared-environment variables to install.
    pub environment: &'a [(&'a str, &'a str)],
    /// Bounded wait before the group is killed.
    pub timeout: Duration,
}

/// Spawned leader plus the group it owns.
pub struct MacOsManagedChild {
    child: Child,
    area: MacOsManagedArea,
    status: Option<ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

impl MacOsManagedChild {
    /// Spawns one leader in a fresh process group.
    ///
    /// # Errors
    /// Returns invalid or unavailable without retaining a partially spawned group.
    pub fn spawn(spec: &MacOsCommandSpec<'_>) -> Result<Self, CommandError> {
        if !spec.executable.is_absolute() {
            return Err(CommandError::Invalid);
        }
        let mut command = Command::new(spec.executable);
        command
            .args(spec.arguments)
            .current_dir(spec.cwd)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        for (key, value) in spec.environment {
            command.env(key, value);
        }
        let mut child = command.spawn().map_err(|_| CommandError::Unavailable)?;
        let pgid = child.id() as i32;
        let streams = match (
            child.stdout.as_ref().map(|stream| stream.as_raw_fd()),
            child.stderr.as_ref().map(|stream| stream.as_raw_fd()),
        ) {
            (Some(stdout), Some(stderr)) => Some((stdout, stderr)),
            _ => None,
        };
        if !streams
            .is_some_and(|(stdout, stderr)| set_nonblocking(stdout) && set_nonblocking(stderr))
        {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
            let _ = child.wait();
            return Err(CommandError::Unavailable);
        }
        let mut identity = [0_u8; 100];
        identity[..13].copy_from_slice(b"macos-area-v1");
        identity[13..17].copy_from_slice(&pgid.to_be_bytes());
        if unsafe { libc::getentropy(identity[17..33].as_mut_ptr().cast(), 16) } != 0 {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
            let _ = child.wait();
            return Err(CommandError::Unavailable);
        }
        Ok(Self {
            child,
            area: MacOsManagedArea::new(pgid, MacOsAreaIdentity::from_bytes(identity)),
            status: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        })
    }

    /// Area owned by this leader.
    #[must_use]
    pub const fn area(&self) -> &MacOsManagedArea {
        &self.area
    }

    /// Waits for the leader, killing the whole group on timeout or error.
    ///
    /// # Errors
    /// Returns timeout after the group was killed, or area failure.
    pub fn wait(
        &mut self,
        timeout: Duration,
    ) -> Result<LinuxLeaderExitObservationV1, CommandError> {
        let deadline = Instant::now() + timeout;
        loop {
            self.drain();
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.area.terminate();
                    self.drain();
                    self.status = Some(status);
                    return Ok(LinuxLeaderExitObservationV1::from_status(status));
                }
                Err(_) => {
                    self.area.terminate();
                    let _ = self.child.wait();
                    return Err(CommandError::Area);
                }
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                self.area.terminate();
                let status = self.child.wait().map_err(|_| CommandError::Area)?;
                self.status = Some(status);
                self.drain();
                let _ = self.area.prove_empty(Duration::from_secs(2));
                return Err(CommandError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Completed status, if the leader was reaped.
    #[must_use]
    pub const fn status(&self) -> Option<ExitStatus> {
        self.status
    }

    /// Classified terminal kind, if reaped.
    #[must_use]
    pub fn exit_kind(&self) -> Option<LinuxLeaderExitKindV1> {
        self.status
            .map(|status| LinuxLeaderExitObservationV1::from_status(status).kind())
    }

    /// Captured stdout after bounded draining.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Captured stderr after bounded draining.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Whether stdout was truncated at the bound.
    #[must_use]
    pub const fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    /// Whether stderr was truncated at the bound.
    #[must_use]
    pub const fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }

    fn drain(&mut self) {
        if let Some(stdout) = self.child.stdout.as_mut() {
            drain_into(stdout, &mut self.stdout, &mut self.stdout_truncated);
        }
        if let Some(stderr) = self.child.stderr.as_mut() {
            drain_into(stderr, &mut self.stderr, &mut self.stderr_truncated);
        }
    }
}

impl Drop for MacOsManagedChild {
    fn drop(&mut self) {
        if self.status.is_none() {
            self.area.terminate();
            let _ = self.child.wait();
        }
    }
}

fn set_nonblocking(fd: i32) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0
}

fn drain_into(reader: &mut impl Read, bytes: &mut Vec<u8>, truncated: &mut bool) {
    let mut buffer = [0_u8; 1024];
    for _ in 0..16 {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let keep = count.min(MAX_OUTPUT_BYTES.saturating_sub(bytes.len()));
                bytes.extend_from_slice(&buffer[..keep]);
                *truncated |= keep < count;
            }
        }
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
