use super::*;
use runne_platform::local_command_linux::LinuxCommandOutputLimitsV1;
use std::time::Instant;

fn limits(stdout: usize, stderr: usize) -> LinuxCommandOutputLimitsV1 {
    LinuxCommandOutputLimitsV1::new(stdout, stderr).expect("bounded output limits")
}

fn collect_until_complete(
    child: &mut runne_platform::local_command_linux::GatedLinuxChild<'_>,
    timeout: Duration,
) -> (Vec<u8>, Vec<u8>, bool, bool, u64, u64, bool, i32) {
    let deadline = Instant::now() + timeout;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;
    let mut status = None;
    let mut observed = (0_u64, 0_u64, false);
    loop {
        child.poll_output().expect("bounded output poll");
        let chunk = child.take_output();
        observed.0 = observed.0.max(chunk.stdout_observed_bytes);
        observed.1 = observed.1.max(chunk.stderr_observed_bytes);
        observed.2 |= chunk.observed_bytes_overflowed;
        assert!(chunk.stdout.len() + chunk.stderr.len() <= 8 * 1024);
        stdout.extend(chunk.stdout);
        stderr.extend(chunk.stderr);
        stdout_truncated |= chunk.stdout_truncated;
        stderr_truncated |= chunk.stderr_truncated;
        status = child.try_wait().expect("leader poll").or(status);
        let latest = child.take_output();
        observed.0 = observed.0.max(latest.stdout_observed_bytes);
        observed.1 = observed.1.max(latest.stderr_observed_bytes);
        observed.2 |= latest.observed_bytes_overflowed;
        status = latest.leader_exit_code.or(status);
        if let (Some(status), true, true) = (status, latest.stdout_eof, latest.stderr_eof) {
            return (
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                observed.0,
                observed.1,
                observed.2,
                status,
            );
        }
        assert!(
            Instant::now() < deadline,
            "output pipe or child did not close"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn sealed_input_is_rewound_and_output_is_bounded_with_sticky_truncation() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: sealed_input_is_rewound_and_output_is_bounded_with_sticky_truncation");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell");
    let command = spec(
        &exe,
        &workspace_fd,
        &cwd,
        OsString::from("read value; printf 'out:%s' \"$value\"; printf 'err:%s' \"$value\" >&2"),
        Vec::new(),
    );
    let mut child = command
        .spawn_gated_with_io(&area, b"payload\n", limits(5, 4))
        .expect("bounded stdio child");
    child.release().expect("release admitted child");
    let (stdout, stderr, out_truncated, err_truncated, out_seen, err_seen, overflowed, status) =
        collect_until_complete(&mut child, Duration::from_secs(5));
    assert_eq!(stdout, b"out:p");
    assert_eq!(stderr, b"err:");
    assert!(out_truncated && err_truncated);
    assert_eq!((out_seen, err_seen, overflowed), (11, 11, false));
    assert_eq!(status, 0);
    assert_eq!(
        child.try_wait().unwrap(),
        Some(0),
        "leader exit is retained"
    );
    drop(child);
    assert!(!area.is_populated().expect("empty exact area"));
    area.remove();
}

#[test]
fn output_larger_than_pipe_capacity_drains_without_blocking_and_reports_eof() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: output_larger_than_pipe_capacity_drains_without_blocking_and_reports_eof");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell");
    let command = spec(
        &exe,
        &workspace_fd,
        &cwd,
        OsString::from(
            "i=0; while [ $i -lt 12000 ]; do printf 0123456789; printf abcdefghij >&2; i=$((i+1)); done",
        ),
        Vec::new(),
    );
    let mut child = command
        .spawn_gated_with_io(&area, b"", limits(16, 4))
        .expect("flood child");
    child.release().expect("release flood child");
    let (stdout, stderr, out_truncated, err_truncated, out_seen, err_seen, overflowed, status) =
        collect_until_complete(&mut child, Duration::from_secs(10));
    assert_eq!(stdout, b"0123456789012345");
    assert_eq!(stderr, b"abcd");
    assert!(out_truncated && err_truncated);
    assert_eq!((out_seen, err_seen, overflowed), (120_000, 120_000, false));
    assert_eq!(status, 0);
    drop(child);
    assert!(!area.is_populated().expect("empty exact area"));
    area.remove();
}

#[test]
fn pipe_eof_is_reported_after_leader_exit_and_descendant_close() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: pipe_eof_is_reported_after_leader_exit_and_descendant_close");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell");
    let command = spec(
        &exe,
        &workspace_fd,
        &cwd,
        OsString::from("sleep 0.2 & exit 0"),
        Vec::new(),
    );
    let mut child = command
        .spawn_gated_with_io(&area, b"", limits(16, 16))
        .expect("descendant child");
    child.release().expect("release descendant child");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut leader_exit = None;
    let mut saw_leader_before_eof = false;
    let mut streams_eof = false;
    while Instant::now() < deadline {
        child.poll_output().expect("poll descendant pipes");
        let _ = child.take_output();
        leader_exit = child.try_wait().expect("leader poll").or(leader_exit);
        let state = child.take_output();
        saw_leader_before_eof |= leader_exit == Some(0) && !state.stdout_eof;
        streams_eof = state.stdout_eof && state.stderr_eof;
        if streams_eof && leader_exit.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(leader_exit, Some(0));
    assert!(saw_leader_before_eof, "leader exit must not imply pipe EOF");
    assert!(streams_eof);
    drop(child);
    assert!(!area.is_populated().expect("descendant exited"));
    area.remove();
}

#[test]
fn cancellation_before_release_with_io_never_runs_or_leaves_the_child() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: cancellation_before_release_with_io_never_runs_or_leaves_the_child");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell");
    let marker = workspace.0.join("cancelled-command-ran");
    let script = OsString::from(format!("printf executed > '{}'", marker.display()));
    let command = spec(&exe, &workspace_fd, &cwd, script, Vec::new());
    let child = command
        .spawn_gated_with_io(&area, b"unused", limits(32, 32))
        .expect("gated child");
    assert!(area.is_populated().expect("gated child is present"));
    child.cancel(Duration::ZERO).expect("cancel before release");
    assert!(!marker.exists(), "unreleased command must not execute");
    assert!(!area.is_populated().expect("cancelled area empty"));
    area.remove();
}

#[test]
fn io_limits_reject_oversize_configuration() {
    assert_eq!(
        LinuxCommandOutputLimitsV1::new(64 * 1024 + 1, 0),
        Err(LinuxCommandError::Invalid)
    );
}
