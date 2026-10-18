use super::*;
use rustix::process::{Signal, pidfd_send_signal};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

fn isolated(test: &str, mode: &str) {
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test, "--nocapture"])
        .env("X2_SIGNAL_CASE", mode)
        .output()
        .expect("isolated signal test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let all_output = format!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "isolated test failed: {all_output}"
    );
    if all_output.contains("SKIP:") {
        eprintln!("SKIP: isolated kernel fixture unavailable");
    } else {
        assert!(
            all_output.contains("RUN:"),
            "isolated test did not execute: {all_output}"
        );
        eprintln!("RUN: isolated {test}");
    }
}

unsafe extern "C" fn noop_signal(_: libc::c_int) {}

struct SignalAction(libc::c_int, libc::sigaction);
impl SignalAction {
    fn install(signal: libc::c_int, handler: usize) -> Self {
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = handler;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        let mut old = unsafe { std::mem::zeroed::<libc::sigaction>() };
        assert_eq!(unsafe { libc::sigaction(signal, &action, &mut old) }, 0);
        Self(signal, old)
    }
}
impl Drop for SignalAction {
    fn drop(&mut self) {
        unsafe { libc::sigaction(self.0, &self.1, std::ptr::null_mut()) };
    }
}

fn pidfd(pid: u32) -> OwnedFd {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    assert!(raw >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(raw as i32) }
}

#[test]
fn inherited_handler_is_reset_before_unblocking() {
    if std::env::var_os("X2_SIGNAL_CASE").is_none() {
        isolated(
            "signal::inherited_handler_is_reset_before_unblocking",
            "run",
        );
        return;
    }
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: inherited_handler_is_reset_before_unblocking");
    let _action = SignalAction::install(libc::SIGUSR1, noop_signal as *const () as usize);
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell");
    let marker = workspace.0.join("inherited-handler-ran");
    let command = spec(
        &exe,
        &workspace_fd,
        &cwd,
        OsString::from(format!("printf ran > '{}'", marker.display())),
        Vec::new(),
    );
    let child = command.spawn_gated(&area).expect("gated child");
    pidfd(child.pid()).pipe_send(Signal::USR1);
    let child = {
        let mut child = child;
        child.release().expect("release");
        child
    };
    assert_eq!(
        child.wait(Duration::from_secs(5)).expect("signal exit"),
        128 + libc::SIGUSR1
    );
    assert!(
        !marker.exists(),
        "inherited handler must not run before exec"
    );
    assert!(!area.is_populated().expect("empty area"));
    area.remove();
}

trait PidfdSignal {
    fn pipe_send(&self, signal: Signal);
}
impl PidfdSignal for OwnedFd {
    fn pipe_send(&self, signal: Signal) {
        pidfd_send_signal(self, signal).expect("pidfd signal");
    }
}

unsafe extern "C" fn noop_child(_: libc::c_int) {}

#[test]
fn caught_sigchld_handler_does_not_break_owned_wait() {
    if std::env::var_os("X2_SIGNAL_CASE").is_none() {
        isolated(
            "signal::caught_sigchld_handler_does_not_break_owned_wait",
            "run",
        );
        return;
    }
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: caught_sigchld_handler_does_not_break_owned_wait");
    let _action = SignalAction::install(libc::SIGCHLD, noop_child as *const () as usize);
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
    let mut child = command
        .spawn_gated(&area)
        .expect("gated child with caught SIGCHLD");
    child.release().expect("release");
    assert_eq!(child.wait(Duration::from_secs(5)).expect("owned wait"), 0);
    assert!(!area.is_populated().expect("empty area"));
    area.remove();
}

#[test]
fn release_after_peer_death_cannot_raise_sigpipe() {
    if std::env::var_os("X2_SIGNAL_CASE").is_none() {
        isolated(
            "signal::release_after_peer_death_cannot_raise_sigpipe",
            "run",
        );
        return;
    }
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: release_after_peer_death_cannot_raise_sigpipe");
    let _action = SignalAction::install(libc::SIGPIPE, libc::SIG_DFL);
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell");
    let marker = workspace.0.join("must-not-run");
    let command = spec(
        &exe,
        &workspace_fd,
        &cwd,
        OsString::from(format!("printf ran > '{}'", marker.display())),
        Vec::new(),
    );
    let mut child = command.spawn_gated(&area).expect("gated child");
    let child_pidfd = pidfd(child.pid());
    child_pidfd.pipe_send(Signal::KILL);
    let mut poll = libc::pollfd {
        fd: child_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut poll, 1, 3000) },
        1,
        "child death bounded"
    );
    assert!(child.release().is_err(), "dead peer release should fail");
    drop(child);
    assert!(!marker.exists());
    // The killed child may still be listed in the area cgroup for a short
    // window after the observed death until its reap completes; wait bounded.
    let empty_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while area.is_populated().expect("empty area") {
        assert!(
            std::time::Instant::now() < empty_deadline,
            "killed child stayed in the area after death"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    area.remove();
}
