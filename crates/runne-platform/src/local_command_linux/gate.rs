use super::LinuxCommandError;
use std::os::fd::{AsRawFd, OwnedFd};
mod seccomp;

pub(in crate::local_command_linux) fn prepare_composite_filter_probe()
-> Option<seccomp::PreparedFilter> {
    seccomp::prepare(true, false, None)
}

pub(in crate::local_command_linux) unsafe fn install_composite_filter_probe(
    filter: &seccomp::PreparedFilter,
) -> i32 {
    unsafe { seccomp::install(filter) }
}

pub(super) fn prepare_seccomp(
    composite: bool,
    network_none: bool,
    filesystem: Option<super::policy::NativeFsProfile>,
) -> Option<seccomp::PreparedFilter> {
    seccomp::prepare(composite, network_none, filesystem)
}

/// Never-returning raw `exit_group` used by gated children (glibc's `_exit`
/// wrapper is avoided in children; see `enter`).
pub(in crate::local_command_linux) fn exit_raw(code: libc::c_int) -> ! {
    loop {
        // SAFETY: exit_group never returns to its caller.
        unsafe { libc::syscall(libc::SYS_exit_group, code) };
    }
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
    _network_none: bool,
    seccomp_filter: &seccomp::PreparedFilter,
    mount_targets: Vec<*const libc::c_char>,
    protected_regular: Vec<i32>,
    device_targets: Vec<*const libc::c_char>,
    device_source_paths: Vec<*const libc::c_char>,
) -> ! {
    let fds = keep.each_ref().map(|fd| fd.as_raw_fd());
    // Fork child: no allocation, formatting, mutexes, destructors, or Rust IO
    // after this point, and no glibc wrapper calls either: this child is a
    // single-threaded clone of a multi-threaded parent, so glibc wrappers can
    // enter cross-thread machinery (setxid coordination, lazy PLT resolution
    // under the dynamic loader lock) whose inherited state never makes
    // progress here and blocks forever before the READY byte. Every entry
    // below is a raw syscall through the already-resolved `syscall` slot.
    unsafe {
        if close_except(&retained).is_err() {
            exit_raw(120);
        }
        if libc::syscall(libc::SYS_dup3, fds[5], 0, 0) < 0
            || libc::syscall(libc::SYS_dup3, fds[6], 1, 0) < 0
            || libc::syscall(libc::SYS_dup3, fds[7], 2, 0) < 0
        {
            exit_raw(121);
        }
        if libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        ) != 0
            || (!composite && libc::syscall(libc::SYS_getppid) as i32 != parent_pid)
            || (composite && libc::syscall(libc::SYS_getppid) != 0)
        {
            exit_raw(123);
        }
        if reset_dispositions() != 0 {
            exit_raw(123);
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
            exit_raw(129);
        }
        if libc::syscall(libc::SYS_fchdir, fds[2]) != 0 {
            exit_raw(122);
        }
        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            exit_raw(124);
        }
        if apply_landlock && libc::syscall(libc::SYS_landlock_restrict_self, fds[4], 0u32) != 0 {
            exit_raw(125);
        }
        for fd in [fds[2], fds[3], fds[4], fds[5], fds[6], fds[7]] {
            libc::syscall(libc::SYS_close, fd);
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
            exit_raw(123);
        }
        if libc::syscall(
            libc::SYS_sendto,
            fds[0],
            b"R".as_ptr(),
            1usize,
            libc::MSG_NOSIGNAL,
            std::ptr::null::<u64>(),
            0usize,
        ) != 1
        {
            exit_raw(126);
        }
        if !composite {
            let self_pid = libc::syscall(libc::SYS_getpid) as i32;
            if libc::syscall(libc::SYS_kill, self_pid, libc::SIGSTOP) != 0 {
                exit_raw(127);
            }
        }
        let mut go = 0u8;
        if libc::syscall(
            libc::SYS_recvfrom,
            fds[0],
            (&mut go as *mut u8).cast::<libc::c_void>(),
            1usize,
            0,
            std::ptr::null::<u64>(),
            std::ptr::null_mut::<u64>(),
        ) != 1
            || go != b'G'
        {
            exit_raw(128);
        }
        libc::syscall(libc::SYS_close, fds[0]);
        if seccomp::install(seccomp_filter) != 0 {
            exit_raw(124);
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
        exit_raw(127);
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

/// Kernel `rt_sigaction` layout used by the raw syscall (glibc's own
/// `sigaction` wrapper is avoided in the child: see `enter`).
#[repr(C)]
struct RawSigaction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

unsafe fn reset_dispositions() -> i32 {
    for signal in 1..=64_i32 {
        if signal != libc::SIGKILL && signal != libc::SIGSTOP {
            let action = RawSigaction {
                handler: 0,
                flags: 0,
                restorer: 0,
                mask: 0,
            };
            // Raw rt_sigaction over the full kernel signal range 1..=64
            // (glibc-only reservations do not exist here; signals 32 and 33
            // are reset as well). A call with these valid arguments has no
            // expected failure mode, so any raw error fails closed.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_rt_sigaction,
                    signal,
                    &action,
                    std::ptr::null::<u64>(),
                    8usize,
                )
            };
            if result != 0 {
                return -1;
            }
        }
    }
    0
}
