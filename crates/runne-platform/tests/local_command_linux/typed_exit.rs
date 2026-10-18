use super::*;
use runne_platform::local_command_linux::{LinuxCommandOutputLimitsV1, LinuxLeaderExitKindV1};
use rustix::process::{Signal, pidfd_send_signal};
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Instant;

fn limits(stdout: usize, stderr: usize) -> LinuxCommandOutputLimitsV1 {
    LinuxCommandOutputLimitsV1::new(stdout, stderr).expect("bounded output limits")
}

#[test]
fn owned_waitpid_distinguishes_exit_137_and_preserves_bounded_output() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: owned_waitpid_distinguishes_exit_137_and_preserves_bounded_output");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell");
    let command = spec(
        &exe,
        &workspace_fd,
        &cwd,
        OsString::from("printf OUT-12345; printf ERR-12345 >&2; exit 137"),
        Vec::new(),
    );
    let mut child = command
        .spawn_gated_with_io(&area, b"", limits(3, 2))
        .expect("bounded output child");
    assert_eq!(child.try_wait().expect("pre-release poll"), None);
    assert_eq!(child.leader_exit_observation(), None);
    assert_eq!(child.take_output().leader_exit_code, None);
    child.release().expect("release exit 137 child");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut stdout_observed = 0;
    let mut stderr_observed = 0;
    let mut observed_overflowed = false;
    let mut output_status = None;
    let mut status = None;
    while Instant::now() < deadline {
        child.poll_output().expect("poll bounded output");
        let chunk = child.take_output();
        stdout.extend(chunk.stdout);
        stderr.extend(chunk.stderr);
        stdout_truncated |= chunk.stdout_truncated;
        stderr_truncated |= chunk.stderr_truncated;
        stdout_eof = chunk.stdout_eof;
        stderr_eof = chunk.stderr_eof;
        stdout_observed = stdout_observed.max(chunk.stdout_observed_bytes);
        stderr_observed = stderr_observed.max(chunk.stderr_observed_bytes);
        observed_overflowed |= chunk.observed_bytes_overflowed;
        output_status = chunk.leader_exit_code.or(output_status);
        status = child.try_wait().expect("poll owned leader").or(status);
        if status.is_some() && stdout_eof && stderr_eof {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(status, Some(137));
    assert_eq!(stdout, b"OUT");
    assert_eq!(stderr, b"ER");
    assert!(stdout_truncated && stderr_truncated);
    assert!(stdout_eof && stderr_eof);
    assert_eq!(
        (stdout_observed, stderr_observed, observed_overflowed),
        (9, 9, false)
    );
    output_status = child.take_output().leader_exit_code.or(output_status);
    assert_eq!(output_status, Some(137));
    assert_eq!(
        child.leader_exit_observation().map(|exit| exit.kind()),
        Some(LinuxLeaderExitKindV1::Exited { code: 137 })
    );
    assert_eq!(child.try_wait().expect("cached leader result"), Some(137));
    assert_eq!(child.take_output().leader_exit_code, Some(137));
    drop(child);
    assert!(!area.is_populated().expect("empty exact area"));
    area.remove();
}

#[test]
fn owned_waitpid_classifies_sigkill_without_guessing_from_legacy_137() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: owned_waitpid_classifies_sigkill_without_guessing_from_legacy_137");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell");
    let command = spec(
        &exe,
        &workspace_fd,
        &cwd,
        OsString::from("exit 0"),
        Vec::new(),
    );
    let mut child = command.spawn_gated(&area).expect("unreleased gated child");
    assert_eq!(child.try_wait().expect("pre-signal poll"), None);
    assert_eq!(child.leader_exit_observation(), None);
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.pid(), 0u32) };
    assert!(raw_pidfd >= 0, "pidfd_open failed");
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd as i32) };
    pidfd_send_signal(&pidfd, Signal::KILL).expect("kill held gate child");

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll signaled leader") {
            break status;
        }
        assert!(Instant::now() < deadline, "bounded SIGKILL wait");
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(status, 137);
    assert_eq!(
        child.leader_exit_observation().map(|exit| exit.kind()),
        Some(LinuxLeaderExitKindV1::Signaled {
            signal: libc::SIGKILL,
            core_dumped: false,
        })
    );
    assert_eq!(child.try_wait().expect("cached signaled result"), Some(137));
    drop(child);
    assert!(!area.is_populated().expect("empty exact area"));
    area.remove();
}
