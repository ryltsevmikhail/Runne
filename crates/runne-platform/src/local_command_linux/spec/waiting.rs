use super::{GatedLinuxChild, LinuxCommandError, LinuxLeaderExitObservationV1};
use std::time::{Duration, Instant};

impl GatedLinuxChild<'_> {
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
            let observation = LinuxLeaderExitObservationV1::decode_wait_status(status)?;
            let exit_code = observation.legacy_exit_code();
            self.leader_exit = Some(observation);
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

    /// Returns the cached outcome obtained by this handle's actual `waitpid` call.
    #[must_use]
    pub fn leader_exit_observation(&self) -> Option<&LinuxLeaderExitObservationV1> {
        self.leader_exit.as_ref()
    }

    pub(super) fn reap(&mut self, timeout: Duration) -> Result<i32, LinuxCommandError> {
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
