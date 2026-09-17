use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use super::VerifiedInstalledQualificationGuiExecutor;

const OPEN_DEADLINE: Duration = Duration::from_secs(10);

impl VerifiedInstalledQualificationGuiExecutor {
    /// Opens only the retained fixed installed application after fresh admission.
    ///
    /// # Limitation
    ///
    /// `LaunchServices` accepts a pathname rather than the retained package
    /// descriptor. The admission is revalidated after `/usr/bin/open` returns,
    /// so a detected package replacement never returns this capability.
    #[must_use]
    pub fn open_installed_application(self) -> Option<Self> {
        let fresh = self.revalidate()?;
        let deadline = Instant::now().checked_add(OPEN_DEADLINE)?;
        let mut child = Command::new("/usr/bin/open")
            .arg(&fresh.paths.application)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let status = wait_for_open(&mut child, deadline)?;
        status.success().then_some(())?;
        fresh.revalidate()
    }
}

fn wait_for_open(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_launch_wait_kills_and_reaps_its_child() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn disposable child");
        assert!(wait_for_open(&mut child, Instant::now()).is_none());
        assert!(child.try_wait().expect("child status").is_some());
    }
}
