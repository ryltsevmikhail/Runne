use super::LinuxCommandError;
use std::os::fd::{AsRawFd, OwnedFd};
mod seccomp;

pub(in crate::local_command_linux) unsafe fn install_composite_filter_probe() -> i32 {
    unsafe { seccomp::install(true, false) }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enter(
    keep: [OwnedFd; 8],
    _protected_keep: Vec<OwnedFd>,
    protected_fds: Vec<i32>,
    retained: Vec<i32>,
    parent_pid: i32,
    argv: *const *const u8,
    env: *const *const u8,
    apply_landlock: bool,
    composite: bool,
    network_none: bool,
    mount_targets: Vec<*const libc::c_char>,
    protected_regular: Vec<i32>,
    device_targets: Vec<*const libc::c_char>,
    device_source_paths: Vec<*const libc::c_char>,
) -> ! {
    let fds = keep.each_ref().map(|fd| fd.as_raw_fd());
    // Fork child: no allocation, formatting, mutexes, destructors, or Rust IO after this point.
    unsafe {
        if close_except(&retained).is_err() {
            libc::_exit(120);
        }
        if libc::dup2(fds[5], 0) < 0 || libc::dup2(fds[6], 1) < 0 || libc::dup2(fds[7], 2) < 0 {
            libc::_exit(121);
        }
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
            || (!composite && libc::getppid() != parent_pid)
            || (composite && libc::getppid() != 0)
        {
            libc::_exit(123);
        }
        if reset_dispositions() != 0 {
            libc::_exit(123);
        }
        if composite
            && !super::child::composite::enter_child(
                fds[0],
                &mount_targets,
                &protected_fds,
                &protected_regular,
                &device_targets,
                &device_source_paths,
            )
        {
            libc::_exit(129);
        }
        if libc::fchdir(fds[2]) != 0 {
            libc::_exit(122);
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            libc::_exit(124);
        }
        if apply_landlock && libc::syscall(libc::SYS_landlock_restrict_self, fds[4], 0u32) != 0 {
            libc::_exit(125);
        }
        for fd in [fds[2], fds[3], fds[4], fds[5], fds[6], fds[7]] {
            libc::close(fd);
        }
        let empty_mask = 0u64;
        if libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &empty_mask,
            std::ptr::null::<u64>(),
            8usize,
        ) != 0
        {
            libc::_exit(123);
        }
        if libc::send(fds[0], b"R".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) != 1 {
            libc::_exit(126);
        }
        if !composite && libc::kill(libc::getpid(), libc::SIGSTOP) != 0 {
            libc::_exit(127);
        }
        let mut go = 0u8;
        if libc::recv(fds[0], (&mut go as *mut u8).cast(), 1, 0) != 1 || go != b'G' {
            libc::_exit(128);
        }
        libc::close(fds[0]);
        if seccomp::install(composite, network_none) != 0 {
            libc::_exit(124);
        }
        let empty = b"\0";
        libc::syscall(
            libc::SYS_execveat,
            fds[1],
            empty.as_ptr(),
            argv,
            env,
            libc::AT_EMPTY_PATH,
        );
        libc::_exit(127);
    }
}
unsafe fn close_except(keep: &[i32]) -> Result<(), ()> {
    let mut start = 3u32;
    for fd in keep {
        let fd = *fd as u32;
        if start < fd && unsafe { libc::syscall(libc::SYS_close_range, start, fd - 1, 0u32) } != 0 {
            return Err(());
        }
        start = fd + 1;
    }
    if unsafe { libc::syscall(libc::SYS_close_range, start, u32::MAX, 0u32) } != 0 {
        return Err(());
    }
    Ok(())
}

pub(super) fn write_byte(fd: i32, byte: u8) -> Result<(), LinuxCommandError> {
    // SAFETY: the pointer references one initialized byte and fd is held by caller.
    if unsafe { libc::send(fd, (&byte as *const u8).cast(), 1, libc::MSG_NOSIGNAL) } == 1 {
        Ok(())
    } else {
        Err(LinuxCommandError::Unverified)
    }
}

unsafe fn reset_dispositions() -> i32 {
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = libc::SIG_DFL;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return -1;
    }
    for signal in 1..=libc::SIGRTMAX() {
        if signal != libc::SIGKILL && signal != libc::SIGSTOP {
            // libc reserves two real-time signals for its thread runtime, so
            // applications cannot install handlers for those signal numbers.
            if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0
                && unsafe { *libc::__errno_location() } != libc::EINVAL
            {
                return -1;
            }
        }
    }
    0
}
