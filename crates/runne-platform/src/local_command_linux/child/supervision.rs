use super::super::LinuxCommandError;
use rustix::process::Pid;
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const GATE_TIMEOUT: Duration = Duration::from_secs(3);
const FD_MIN: i32 = 50;

pub(super) fn validate_sigchld() -> Result<(), LinuxCommandError> {
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || action.sa_sigaction == libc::SIG_IGN
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err(LinuxCommandError::Unavailable);
    }
    Ok(())
}

pub(super) fn dup(fd: i32) -> Result<OwnedFd, LinuxCommandError> {
    let result = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, FD_MIN) };
    if result < 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(result) })
}

pub(super) fn read_ready(fd: i32) -> Result<(), LinuxCommandError> {
    let deadline = Instant::now() + GATE_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(LinuxCommandError::Unverified);
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, remaining.as_millis() as i32) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if result != 1 {
            return Err(LinuxCommandError::Unverified);
        }
        let mut byte = 0u8;
        if unsafe { libc::recv(fd, (&mut byte as *mut u8).cast(), 1, 0) } != 1 {
            return Err(LinuxCommandError::Unverified);
        }
        return if byte == b'R' {
            Ok(())
        } else {
            Err(LinuxCommandError::Unverified)
        };
    }
}

pub(super) fn wait_stopped(pid: Pid) -> Result<(), LinuxCommandError> {
    let deadline = Instant::now() + GATE_TIMEOUT;
    loop {
        let mut status = 0;
        let got = unsafe {
            libc::waitpid(
                pid.as_raw_pid(),
                &mut status,
                libc::WNOHANG | libc::WUNTRACED,
            )
        };
        if got == pid.as_raw_pid() {
            return if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
                Ok(())
            } else {
                Err(LinuxCommandError::Unverified)
            };
        }
        if got < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if got < 0 || Instant::now() >= deadline {
            return Err(LinuxCommandError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

pub(in crate::local_command_linux) fn reap_bounded_or_defer(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid
            || (result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
        {
            return;
        }
        if Instant::now() >= deadline {
            let _ = std::thread::Builder::new().spawn(move || {
                loop {
                    let mut status = 0;
                    let result = unsafe { libc::waitpid(pid, &mut status, 0) };
                    if result == pid
                        || (result < 0
                            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
                    {
                        break;
                    }
                }
            });
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub(super) fn kill_and_reap(pid: Pid, pidfd: &OwnedFd) {
    let _ = rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL);
    reap_bounded_or_defer(pid.as_raw_pid());
}
