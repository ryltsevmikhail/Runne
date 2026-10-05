use super::*;

pub(in crate::application) fn capture_existing_target_snapshot(
    files: &LinuxCommandWorkspaceFiles,
    path: &str,
) -> Result<VersionV1, ()> {
    let path = std::ffi::CString::new(path).map_err(|_| ())?;
    let fd = unsafe {
        libc::openat(
            files.workspace().as_raw_fd(),
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as usize > 8 * 1024
    {
        return Err(());
    }
    Ok(VersionV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: stat.st_size as u64,
        mtime_sec: stat.st_mtime,
        mtime_nsec: stat.st_mtime_nsec,
        ctime_sec: stat.st_ctime,
        ctime_nsec: stat.st_ctime_nsec,
    })
}
