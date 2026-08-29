use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

use super::RetainedWriterProcess;

mod process_start_identity;
use process_start_identity::observed_start_identity;

#[cfg(test)]
#[path = "unix/process_start_identity_tests.rs"]
mod process_start_identity_tests;

/// Exact desktop-held Unix child. Its start identity prevents PID reuse from
/// becoming authority while the platform keeps the child waitable.
pub struct UnixRetainedWriterProcess {
    pid: libc::pid_t,
    start_identity: [u8; 32],
}

/// Exact child identity with wait/reap authority but no signaling API.
pub(super) struct UnixWriterReapOnlyProcess {
    pid: libc::pid_t,
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

    pub(super) const fn into_reap_only(self) -> UnixWriterReapOnlyProcess {
        UnixWriterReapOnlyProcess { pid: self.pid }
    }
}

impl UnixWriterReapOnlyProcess {
    pub(super) fn reap(self) -> Result<(), BrokerHandoffError> {
        wait_for_pid(nix::unistd::Pid::from_raw(self.pid))
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
    loop {
        match nix::sys::wait::waitpid(pid, None) {
            Ok(_) => return Ok(()),
            Err(nix::errno::Errno::EINTR) => (),
            Err(_) => return Err(BrokerHandoffError::Unavailable),
        }
    }
}
