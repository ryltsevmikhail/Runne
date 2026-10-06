//! User, mount, and PID namespace setup performed before the READY/GO gate.

use super::super::super::LinuxCommandError;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[path = "credentials.rs"]
mod credentials;

#[repr(C)]
struct ProbeCloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub(super) fn preflight_namespaces() -> Result<(), LinuxCommandError> {
    let mut pair = [0; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(LinuxCommandError::Unavailable);
    }
    let parent = unsafe { OwnedFd::from_raw_fd(pair[0]) };
    let child = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    let mut pidfd = -1i32;
    let args = ProbeCloneArgs {
        flags: 0x1000 | (libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID) as u64,
        pidfd: (&mut pidfd as *mut i32) as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args,
            std::mem::size_of::<ProbeCloneArgs>(),
        )
    };
    if pid == 0 {
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != 0
            {
                libc::_exit(101);
            }
            let mut mapped = 0u8;
            if libc::recv(child.as_raw_fd(), (&mut mapped as *mut u8).cast(), 1, 0) != 1
                || mapped != b'M'
                || libc::setresgid(0, 0, 0) != 0
                || libc::setresuid(0, 0, 0) != 0
                || make_mounts_private() != 0
                || mask_path(c"/sys".as_ptr()) != 0
                || mount_private_proc() != 0
                || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || crate::local_command_linux::gate::install_composite_filter_probe() != 0
            {
                libc::_exit(102);
            }
            libc::_exit(0);
        }
    }
    drop(child);
    if pid < 0 || pidfd < 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    let _pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    let mapped = map_child_identity(pid as i32, parent.as_raw_fd());
    if mapped.is_err() {
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        if result == pid as i32 {
            return if mapped.is_ok() && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                Ok(())
            } else {
                Err(LinuxCommandError::Unavailable)
            };
        }
        if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let _ = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    Err(LinuxCommandError::Unavailable)
}

pub(in crate::local_command_linux) fn map_child_identity(
    pid: i32,
    socket: i32,
) -> Result<(), LinuxCommandError> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let prefix = format!("/proc/{pid}");
    write_map(&format!("{prefix}/setgroups"), "deny\n")?;
    write_map(&format!("{prefix}/uid_map"), &format!("0 {uid} 1\n"))?;
    write_map(&format!("{prefix}/gid_map"), &format!("0 {gid} 1\n"))?;
    if unsafe { libc::send(socket, (&b'M' as *const u8).cast(), 1, libc::MSG_NOSIGNAL) } != 1 {
        return Err(LinuxCommandError::Unavailable);
    }
    Ok(())
}

pub(super) fn validate_host_mounts() -> Result<(), LinuxCommandError> {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| LinuxCommandError::Unavailable)?;
    for line in mounts.lines() {
        let (left, right) = line
            .split_once(" - ")
            .ok_or(LinuxCommandError::Unavailable)?;
        let mountpoint = left
            .split_whitespace()
            .nth(4)
            .ok_or(LinuxCommandError::Unavailable)?;
        let filesystem = right
            .split_whitespace()
            .next()
            .ok_or(LinuxCommandError::Unavailable)?;
        let protected_prefix = match filesystem {
            "proc" => Some("/proc"),
            "sysfs" | "cgroup" | "cgroup2" | "debugfs" | "tracefs" | "securityfs" | "bpf"
            | "pstore" | "configfs" => Some("/sys"),
            "devtmpfs" | "devpts" | "mqueue" => Some("/dev"),
            _ => None,
        };
        if let Some(prefix) = protected_prefix
            && mountpoint != prefix
            && !mountpoint.starts_with(&format!("{prefix}/"))
        {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
    }
    Ok(())
}

pub(in crate::local_command_linux) unsafe fn enter_child(
    socket: i32,
    mount_targets: &[*const libc::c_char],
    protected_fds: &[i32],
    protected_regular_files: &[i32],
    device_targets: &[*const libc::c_char],
    device_source_paths: &[*const libc::c_char],
) -> bool {
    let mut mapped = 0u8;
    if unsafe { libc::recv(socket, (&mut mapped as *mut u8).cast(), 1, 0) } != 1 || mapped != b'M' {
        return false;
    }
    if unsafe { libc::setresgid(0, 0, 0) } != 0
        || unsafe { libc::setresuid(0, 0, 0) } != 0
        || unsafe { make_mounts_private() } != 0
    {
        return false;
    }
    for target in mount_targets {
        if unsafe { mask_tree_fd(*target) } != 0 {
            return false;
        }
    }
    if unsafe { mask_path(c"/sys".as_ptr()) } != 0 {
        return false;
    }
    if unsafe { super::devices::mount_private(device_targets, device_source_paths) } != 0 {
        return false;
    }
    if unsafe { mount_private_proc() } != 0 {
        return false;
    }
    if unsafe { verify_single_link_files(protected_regular_files) } != 0 {
        return false;
    }
    if unsafe { credentials::lock_securebits() } != 0 {
        return false;
    }
    if unsafe { credentials::drop_capabilities() } != 0 {
        return false;
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return false;
    }
    for fd in protected_fds {
        unsafe { libc::close(*fd) };
    }
    true
}

#[path = "namespace/mount.rs"]
mod mount;
use mount::{
    make_mounts_private, mask_path, mask_tree_fd, mount_private_proc, verify_single_link_files,
    write_map,
};
