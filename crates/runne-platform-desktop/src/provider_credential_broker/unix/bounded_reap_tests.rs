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
