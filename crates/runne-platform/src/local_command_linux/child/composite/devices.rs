//! Minimal same-user `/dev` view with only harmless POSIX devices.

use super::super::super::LinuxCommandError;
use rustix::fs::fstat;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(super) struct SafeDevices(Vec<(File, CString, CString)>);

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
            let source = CString::new(format!("/dev/{name}")).unwrap();
            let target = source.clone();
            devices.push((file, target, source));
        }
        Ok(Self(devices))
    }

    pub(super) fn child_descriptors(
        &self,
        descriptors: &mut Vec<OwnedFd>,
    ) -> Result<(Vec<CString>, Vec<CString>), LinuxCommandError> {
        let mut targets = Vec::with_capacity(self.0.len());
        let mut source_paths = Vec::with_capacity(self.0.len());
        for (file, target, source) in &self.0 {
            targets.push(target.clone());
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(LinuxCommandError::Unavailable);
            }
            source_paths.push(source.clone());
            descriptors.push(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        Ok((targets, source_paths))
    }
}

pub(super) unsafe fn mount_private(
    targets: &[*const libc::c_char],
    source_paths: &[*const libc::c_char],
) -> i32 {
    if targets.len() != source_paths.len()
        || unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                c"/dev".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NOEXEC,
                c"mode=755".as_ptr().cast(),
            )
        } != 0
    {
        return -1;
    }
    for (target, source_path) in targets.iter().zip(source_paths) {
        let placeholder = unsafe {
            libc::open(
                *target,
                libc::O_CREAT | libc::O_CLOEXEC | libc::O_RDWR,
                0o600,
            )
        };
        if placeholder < 0 {
            return -1;
        }
        unsafe { libc::close(placeholder) };
        if unsafe {
            libc::mount(
                *source_path,
                *target,
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return -1;
        }
    }
    0
}

const fn makedev(major: u32, minor: u32) -> u64 {
    ((major as u64 & 0x0fff) << 8)
        | (minor as u64 & 0x00ff)
        | ((minor as u64 & 0xffff_ff00) << 12)
        | ((major as u64 & 0xffff_f000) << 32)
}
