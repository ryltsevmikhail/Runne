use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
use std::os::fd::AsFd as _;

use super::RetainedWriterProcess;

pub(super) mod process_start_identity;
use process_start_identity::observed_start_identity;

/// Observes the current process start identity through the platform-owned
/// native adapter, keeping daemon code independent of the native crate.
///
/// # Errors
///
/// Returns a closed broker error when the native process identity cannot be
/// observed or authenticated.
#[cfg(unix)]
pub fn observe_current_process_start() -> Result<[u8; 32], BrokerHandoffError> {
    observed_start_identity(std::process::id())
}

#[cfg(test)]
#[path = "unix/process_start_identity_tests.rs"]
mod process_start_identity_tests;

/// Exact desktop-held Unix child. Its start identity prevents PID reuse from
/// becoming authority while the platform keeps the child waitable.
pub struct UnixRetainedWriterProcess {
    pid: libc::pid_t,
    start_identity: [u8; 32],
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::OwnedFd>,
}

impl UnixRetainedWriterProcess {
    #[cfg(target_os = "macos")]
    pub(super) fn from_pid(pid: nix::unistd::Pid) -> Result<Self, BrokerHandoffError> {
        let start_identity = match observed_start_identity(pid.as_raw().cast_unsigned()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = terminate_and_reap(pid);
                return Err(error);
            }
        };
        Ok(Self {
            pid: pid.as_raw(),
            start_identity,
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn from_spawned(
        pid: libc::pid_t,
        pidfd: std::os::fd::OwnedFd,
    ) -> Result<Self, BrokerHandoffError> {
        let start_identity = observed_start_identity(pid.cast_unsigned())?;
        Ok(Self {
            pid,
            start_identity,
            pidfd: Some(pidfd),
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) const fn test_pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Test-only identity corruption proving kill never targets a mismatched
    /// start identity.
    #[cfg(all(test, target_os = "linux"))]
    pub(super) const fn test_break_start_identity(&mut self) {
        self.start_identity = [0xff; 32];
    }

    #[cfg(target_os = "linux")]
    pub(super) const fn retained_pid(&self) -> libc::pid_t {
        self.pid
    }

    #[cfg(target_os = "linux")]
    pub(super) const fn retained_start_identity(&self) -> [u8; 32] {
        self.start_identity
    }

    #[cfg(target_os = "macos")]
    pub(super) const fn pid(&self) -> libc::pid_t {
        self.pid
    }

    #[cfg(target_os = "macos")]
    pub(super) const fn into_reap_only(self) -> UnixWriterReapOnlyProcess {
        UnixWriterReapOnlyProcess {
            pid: Some(self.pid),
        }
    }
}

/// Exact waitable child, held only while the desktop keeps macOS kill authority.
#[cfg(target_os = "macos")]
pub(super) struct UnixWriterReapOnlyProcess {
    pid: Option<libc::pid_t>,
}

#[cfg(target_os = "macos")]
impl UnixWriterReapOnlyProcess {
    pub(super) fn reap(&mut self) -> Result<(), BrokerHandoffError> {
        self.reap_with_timeout(std::time::Duration::from_secs(2))
    }

    pub(super) fn reap_with_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<(), BrokerHandoffError> {
        let Some(pid) = self.pid else {
            return Ok(());
        };
        wait_for_pid_bounded(nix::unistd::Pid::from_raw(pid), timeout)?;
        self.pid = None;
        Ok(())
    }
}

impl RetainedWriterProcess for UnixRetainedWriterProcess {
    fn writer_start_identity(&self) -> Result<[u8; 32], BrokerHandoffError> {
        (observed_start_identity(self.pid.cast_unsigned())? == self.start_identity)
            .then_some(self.start_identity)
            .ok_or(BrokerHandoffError::Rejected)
    }

    fn terminate_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        #[cfg(target_os = "macos")]
        {
            let _ = self.writer_start_identity()?;
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(self.pid),
                nix::sys::signal::Signal::SIGKILL,
            )
            .map_err(|_| BrokerHandoffError::Unavailable)
        }
        #[cfg(target_os = "linux")]
        {
            let _ = self.writer_start_identity()?;
            let pidfd = self.pidfd.as_ref().ok_or(BrokerHandoffError::Unavailable)?;
            rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL)
                .map_err(|_| BrokerHandoffError::Unavailable)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(BrokerHandoffError::Unavailable)
        }
    }

    fn reap_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        #[cfg(target_os = "macos")]
        {
            wait_for_pid(nix::unistd::Pid::from_raw(self.pid))
        }
        #[cfg(target_os = "linux")]
        {
            let pidfd = self.pidfd.as_ref().ok_or(BrokerHandoffError::Unavailable)?;
            rustix::process::waitid(
                rustix::process::WaitId::PidFd(pidfd.as_fd()),
                rustix::process::WaitIdOptions::EXITED,
            )
            .map_err(|_| BrokerHandoffError::Unavailable)?;
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(BrokerHandoffError::Unavailable)
        }
    }
}

#[cfg(target_os = "macos")]
fn terminate_and_reap(pid: nix::unistd::Pid) -> Result<(), BrokerHandoffError> {
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    wait_for_pid(pid)
}

#[cfg(target_os = "macos")]
fn wait_for_pid(pid: nix::unistd::Pid) -> Result<(), BrokerHandoffError> {
    wait_for_pid_bounded(pid, std::time::Duration::from_secs(2))
}

#[cfg(target_os = "macos")]
fn wait_for_pid_bounded(
    pid: nix::unistd::Pid,
    timeout: std::time::Duration,
) -> Result<(), BrokerHandoffError> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or(BrokerHandoffError::Unavailable)?;
    loop {
        match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                if std::time::Instant::now() >= deadline {
                    return Err(BrokerHandoffError::Unavailable);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(_) => return Ok(()),
            Err(nix::errno::Errno::EINTR) => (),
            Err(_) => return Err(BrokerHandoffError::Unavailable),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod bounded_reap_tests {
    use std::time::{Duration, Instant};

    #[test]
    fn reap_timeout_is_bounded_for_a_live_exact_child() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
        let started = Instant::now();
        assert!(super::wait_for_pid_bounded(pid, Duration::from_millis(20)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn reap_timeout_retains_exact_owner_for_later_kill_and_retry() {
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
        drop(child);
        let mut owner = super::UnixWriterReapOnlyProcess {
            pid: Some(pid.as_raw()),
        };

        assert!(owner.reap_with_timeout(Duration::from_millis(20)).is_err());
        assert_eq!(owner.pid, Some(pid.as_raw()));
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        assert!(owner.reap_with_timeout(Duration::from_secs(1)).is_ok());
        assert_eq!(owner.pid, None);
    }

    #[test]
    fn writer_already_exited_is_observed_and_owner_is_consumed_once() {
        let child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
        drop(child);
        let mut owner = super::UnixWriterReapOnlyProcess {
            pid: Some(pid.as_raw()),
        };

        assert!(owner.reap_with_timeout(Duration::from_secs(1)).is_ok());
        assert_eq!(owner.pid, None);
        assert!(owner.reap_with_timeout(Duration::from_millis(1)).is_ok());
    }

    #[test]
    fn failed_reap_owner_drop_never_starts_a_detached_waiter() {
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
        drop(child);
        {
            let mut owner = super::UnixWriterReapOnlyProcess {
                pid: Some(pid.as_raw()),
            };
            assert!(owner.reap_with_timeout(Duration::from_millis(20)).is_err());
        }

        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        let observed = nix::sys::wait::waitpid(pid, None).unwrap();
        assert!(!matches!(observed, nix::sys::wait::WaitStatus::StillAlive));
    }

    #[test]
    fn substituted_start_identity_never_signals_the_live_child() {
        use crate::provider_credential_broker::RetainedWriterProcess as _;

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut retained = super::UnixRetainedWriterProcess {
            pid: i32::try_from(child.id()).unwrap(),
            start_identity: [0; 32],
        };

        assert!(retained.terminate_retained_child().is_err());
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
