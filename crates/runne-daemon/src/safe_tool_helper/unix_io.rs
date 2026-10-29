use super::*;

pub(super) fn openat(root: &File, path: &CString, flags: i32) -> Result<File, ()> {
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            path.as_ptr(),
            flags | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn reopen_pinned_read(pinned: &File) -> Result<File, &'static str> {
    let proc_path =
        CString::new(format!("/proc/self/fd/{}", pinned.as_raw_fd())).map_err(|_| "read_denied")?;
    let fd = unsafe {
        libc::open(
            proc_path.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("read_denied");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn identity(file: &File) -> Result<IdentityV1, &'static str> {
    let stat = stat(file)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err("root_invalid");
    }
    Ok(IdentityV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

pub(super) fn version(file: &File) -> Result<VersionV1, &'static str> {
    let stat = stat(file)?;
    Ok(VersionV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: u64::try_from(stat.st_size).map_err(|_| "target_invalid")?,
        mtime_sec: stat.st_mtime,
        mtime_nsec: stat.st_mtime_nsec,
        ctime_sec: stat.st_ctime,
        ctime_nsec: stat.st_ctime_nsec,
    })
}

pub(super) fn stat(file: &File) -> Result<libc::stat, &'static str> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err("stat_failed");
    }
    Ok(stat)
}

pub(super) fn regular_single(file: &File) -> Result<bool, &'static str> {
    let stat = stat(file)?;
    Ok(stat.st_mode & libc::S_IFMT == libc::S_IFREG && stat.st_nlink == 1)
}

pub(super) fn read_bounded(file: &File, length: usize) -> Result<Vec<u8>, &'static str> {
    if length > MAX_CONTENT {
        return Err("content_bound");
    }
    let mut bytes = vec![0; length];
    let read = unsafe { libc::pread(file.as_raw_fd(), bytes.as_mut_ptr().cast(), length, 0) };
    if read < 0 || read as usize != length {
        return Err("read_failed");
    }
    Ok(bytes)
}

pub(super) fn write_all(file: &File, bytes: &[u8]) -> Result<(), &'static str> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = unsafe {
            libc::write(
                file.as_raw_fd(),
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count <= 0 {
            return Err("write_failed");
        }
        offset += count as usize;
    }
    Ok(())
}
