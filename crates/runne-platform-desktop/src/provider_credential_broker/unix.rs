use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::RetainedWriterProcess;

mod process_start_identity;
use process_start_identity::observed_start_identity;

/// Observes the current process start identity through the platform-owned
/// native adapter, keeping daemon code independent of the native crate.
///
/// # Errors
///
/// Returns a closed broker error when the native process identity cannot be
/// observed or authenticated.
#[cfg(target_os = "macos")]
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

    fn reap_with_timeout(
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

#[cfg(target_os = "macos")]
impl Drop for UnixWriterReapOnlyProcess {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            retain_reap_ownership(nix::unistd::Pid::from_raw(pid));
        }
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
        #[cfg(not(target_os = "macos"))]
        {
            Err(BrokerHandoffError::Unavailable)
        }
    }

    fn reap_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        #[cfg(target_os = "macos")]
        {
            wait_for_pid(nix::unistd::Pid::from_raw(self.pid))
        }
        #[cfg(not(target_os = "macos"))]
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

#[cfg(target_os = "macos")]
fn retain_reap_ownership(pid: nix::unistd::Pid) {
    let retained = std::sync::Arc::new(pid);
    let worker = std::sync::Arc::clone(&retained);
    if std::thread::Builder::new()
        .name("runne-writer-reaper".into())
        .spawn(move || wait_for_pid_unbounded(*worker))
        .is_err()
    {
        wait_for_pid_unbounded(*retained);
    }
}

#[cfg(target_os = "macos")]
fn wait_for_pid_unbounded(pid: nix::unistd::Pid) {
    loop {
        match nix::sys::wait::waitpid(pid, None) {
            Ok(_) | Err(nix::errno::Errno::ECHILD) => return,
            Err(nix::errno::Errno::EINTR) => (),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
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
    fn final_failed_retry_moves_exact_reap_into_an_independent_owner() {
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
        drop(owner);

        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let independently_reaped = loop {
            match nix::sys::signal::kill(pid, None) {
                Err(nix::errno::Errno::ESRCH) => break true,
                _ if Instant::now() >= deadline => break false,
                _ => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        if !independently_reaped {
            let _ = nix::sys::wait::waitpid(pid, None);
        }
        assert!(independently_reaped);
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
