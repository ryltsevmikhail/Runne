use super::LinuxCommandError;
use std::os::fd::{AsRawFd, OwnedFd};

pub(super) fn enter(
    keep: [OwnedFd; 8],
    retained: [i32; 8],
    parent_pid: i32,
    argv: *const *const u8,
    env: *const *const u8,
) -> ! {
    let fds = keep.each_ref().map(|fd| fd.as_raw_fd());
    // Fork child: no allocation, formatting, mutexes, destructors, or Rust IO after this point.
    unsafe {
        if close_except(retained).is_err() {
            libc::_exit(120);
        }
        if libc::dup2(fds[5], 0) < 0 || libc::dup2(fds[6], 1) < 0 || libc::dup2(fds[7], 2) < 0 {
            libc::_exit(121);
        }
        if libc::fchdir(fds[2]) != 0 {
            libc::_exit(122);
        }
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent_pid
        {
            libc::_exit(123);
        }
        if reset_dispositions() != 0 {
            libc::_exit(123);
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || install_seccomp() != 0 {
            libc::_exit(124);
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, fds[4], 0u32) != 0 {
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
        if libc::kill(libc::getpid(), libc::SIGSTOP) != 0 {
            libc::_exit(127);
        }
        let mut go = 0u8;
        if libc::recv(fds[0], (&mut go as *mut u8).cast(), 1, 0) != 1 || go != b'G' {
            libc::_exit(128);
        }
        libc::close(fds[0]);
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
unsafe fn close_except(keep: [i32; 8]) -> Result<(), ()> {
    let mut start = 3u32;
    for fd in keep {
        let fd = fd as u32;
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

unsafe fn install_seccomp() -> i32 {
    let arch = match std::env::consts::ARCH {
        "x86_64" => 0xc000_003e,
        "aarch64" => 0xc000_00b7,
        "x86" => 0x4000_0003,
        "arm" => 0x4000_0028,
        "riscv64" => 0xc000_00f3,
        _ => return -1,
    };
    let blocked = [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_mount_setattr,
        libc::SYS_clone3,
    ];
    let mut filter = [libc::sock_filter {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    }; 40];
    let mut len = 0usize;
    filter[len] = libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 4,
    };
    len += 1;
    filter[len] = libc::sock_filter {
        code: 0x15,
        jt: 1,
        jf: 0,
        k: arch,
    };
    len += 1;
    filter[len] = libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x8000_0000,
    };
    len += 1;
    filter[len] = libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    };
    len += 1;
    #[cfg(target_arch = "x86_64")]
    {
        filter[len] = libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        };
        len += 1;
        filter[len] = libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0005_0000 | libc::EPERM as u32,
        };
        len += 1;
    }
    for syscall in blocked {
        filter[len] = libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        };
        len += 1;
        filter[len] = libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0005_0000 | libc::EPERM as u32,
        };
        len += 1;
    }
    // Deny clone3; for legacy clone deny every namespace flag while preserving ordinary forks/threads.
    filter[len] = libc::sock_filter {
        code: 0x15,
        jt: 0,
        jf: 4,
        k: libc::SYS_clone as u32,
    };
    len += 1;
    filter[len] = libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 16,
    };
    len += 1;
    filter[len] = libc::sock_filter {
        code: 0x45,
        jt: 0,
        jf: 1,
        k: 0x7e02_0000,
    };
    len += 1;
    filter[len] = libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x0005_0000 | libc::EPERM as u32,
    };
    len += 1;
    filter[len] = libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    };
    len += 1;
    filter[len] = libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff_0000,
    };
    len += 1;
    let mut program = libc::sock_fprog {
        len: len as u16,
        filter: filter.as_mut_ptr(),
    };
    unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program,
        )
    }
}
