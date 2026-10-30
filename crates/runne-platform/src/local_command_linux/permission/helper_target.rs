use super::helper_protocol::{HELPER_MAX_CONTENT, ParsedHelperRequest};
use crate::local_command_linux::LinuxCommandError;
use std::{fs::File, os::fd::AsRawFd};
pub(super) fn check_helper_target(
    parsed: &ParsedHelperRequest,
    workspace: &File,
) -> Result<(), LinuxCommandError> {
    let mut root = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(workspace.as_raw_fd(), &mut root) } != 0
        || root.st_mode & libc::S_IFMT != libc::S_IFDIR
        || root.st_dev as u64 != parsed.observation.root_device
        || root.st_ino as u64 != parsed.observation.root_inode
    {
        return Err(LinuxCommandError::Unverified);
    }
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    let opened = openat2(
        workspace,
        parsed.path.as_c_str(),
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    );
    if parsed.absent {
        return match opened {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            _ => Err(LinuxCommandError::Unverified),
        };
    }
    let file = File::from(opened.map_err(|_| LinuxCommandError::Unverified)?);
    let mut actual = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut actual) } != 0
        || actual.st_mode & libc::S_IFMT
            != if parsed.observation.operation.is_directory() {
                libc::S_IFDIR
            } else {
                libc::S_IFREG
            }
        || (!parsed.observation.operation.is_directory() && actual.st_nlink != 1)
        || actual.st_size < 0
    {
        return Err(LinuxCommandError::Unverified);
    }
    let expected = parsed
        .observation
        .target
        .ok_or(LinuxCommandError::Unverified)?;
    if actual.st_dev as u64 != expected.device
        || actual.st_ino as u64 != expected.inode
        || actual.st_size as u64 != expected.size
        || actual.st_mtime != expected.mtime_sec
        || actual.st_mtime_nsec != expected.mtime_nsec
        || actual.st_ctime != expected.ctime_sec
        || actual.st_ctime_nsec != expected.ctime_nsec
        || (!parsed.observation.operation.is_directory()
            && actual.st_size as u64 > HELPER_MAX_CONTENT as u64)
    {
        return Err(LinuxCommandError::Unverified);
    }
    Ok(())
}
