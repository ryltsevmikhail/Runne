//! Minimal same-user `/dev` view with only harmless POSIX devices.

use super::super::super::LinuxCommandError;
use rustix::fs::fstat;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[path = "devices_identity.rs"]
mod device_identity;

pub(super) struct SafeDevices(Vec<(File, CString)>);

impl SafeDevices {
    pub(super) fn open() -> Result<Self, LinuxCommandError> {
        let mut devices = Vec::new();
        for (name, minor) in [
            ("null", 3),
            ("zero", 5),
            ("full", 7),
            ("random", 8),
            ("urandom", 9),
        ] {
            let file =
                File::open(format!("/dev/{name}")).map_err(|_| LinuxCommandError::Unavailable)?;
            let stat = fstat(&file).map_err(|_| LinuxCommandError::Unavailable)?;
            if stat.st_mode & libc::S_IFMT != libc::S_IFCHR || stat.st_rdev != makedev(1, minor) {
                return Err(LinuxCommandError::CompositePolicyUnenforceable);
            }
            let target = CString::new(format!("/dev/{name}")).unwrap();
            devices.push((file, target));
        }
        Ok(Self(devices))
    }

    pub(super) fn child_descriptors(
        &self,
        descriptors: &mut Vec<OwnedFd>,
    ) -> Result<(Vec<CString>, Vec<CString>), LinuxCommandError> {
        let mut targets = Vec::with_capacity(self.0.len());
        let mut source_paths = Vec::with_capacity(self.0.len());
        for (file, target) in &self.0 {
            targets.push(target.clone());
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(LinuxCommandError::Unavailable);
            }
            // Retain the parent's verified identity for the child to compare
            // against a clone opened through its own mount namespace.
            source_paths.push(CString::new(format!("/proc/self/fd/{fd}")).unwrap());
            descriptors.push(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        Ok((targets, source_paths))
    }
}

pub(super) unsafe fn mount_private(
    targets: &[*const libc::c_char],
    source_paths: &[*const libc::c_char],
) -> i32 {
    // Fork child: only raw syscalls and scalar stack operations. All target
    // paths are the fixed, parent-verified five-device inventory.
    if targets.len() != 5 || targets.len() != source_paths.len() {
        return -1;
    }
    let mut mounts = [-1_i32; 5];
    let mut index = 0;
    while index < 5 {
        // Clone a path in THIS mount namespace before hiding /dev. A held FD
        // opened in the parent's namespace cannot be bound/cloned here.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                libc::AT_FDCWD,
                targets[index],
                1usize | libc::O_CLOEXEC as usize | libc::AT_SYMLINK_NOFOLLOW as usize,
            ) as i32
        };
        if fd < 0 {
            unsafe { close_mounts(&mounts) };
            return -1;
        }
        mounts[index] = fd;
        if !unsafe { device_identity::matches(source_paths[index], fd) } {
            unsafe { close_mounts(&mounts) };
            return -1;
        }
        index += 1;
    }
    if unsafe {
        libc::syscall(
            libc::SYS_mount,
            c"tmpfs".as_ptr(),
            c"/dev".as_ptr(),
            c"tmpfs".as_ptr(),
            (libc::MS_NOSUID | libc::MS_NOEXEC) as usize,
            c"mode=755".as_ptr(),
        )
    } != 0
    {
        unsafe { close_mounts(&mounts) };
        return -1;
    }
    index = 0;
    while index < 5 {
        let placeholder = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                targets[index],
                (libc::O_CREAT | libc::O_CLOEXEC | libc::O_RDWR) as usize,
                0o600,
            ) as i32
        };
        if placeholder < 0 {
            unsafe { close_mounts(&mounts) };
            return -1;
        }
        unsafe { libc::syscall(libc::SYS_close, placeholder) };
        if unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                mounts[index],
                c"".as_ptr(),
                libc::AT_FDCWD,
                targets[index],
                0x4usize,
            )
        } != 0
        {
            unsafe { close_mounts(&mounts) };
            return -1;
        }
        index += 1;
    }
    unsafe { close_mounts(&mounts) };
    0
}
unsafe fn close_mounts(mounts: &[i32; 5]) {
    let mut index = 0;
    while index < 5 {
        if mounts[index] >= 0 {
            unsafe { libc::syscall(libc::SYS_close, mounts[index]) };
        }
        index += 1;
    }
}

const fn makedev(major: u32, minor: u32) -> u64 {
    ((major as u64 & 0x0fff) << 8)
        | (minor as u64 & 0x00ff)
        | ((minor as u64 & 0xffff_ff00) << 12)
        | ((major as u64 & 0xffff_f000) << 32)
}

#[cfg(test)]
#[path = "devices_tests.rs"]
mod tests;
