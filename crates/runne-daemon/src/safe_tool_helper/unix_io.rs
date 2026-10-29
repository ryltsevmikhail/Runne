use super::*;
use crate::safe_tool_helper::platform;

pub(super) fn openat(root: &File, path: &CString, flags: i32) -> Result<File, ()> {
    platform::open_beneath(root, path, flags, 0o600).map_err(|_| ())
}

pub(super) fn reopen_pinned_read(pinned: &File) -> Result<File, &'static str> {
    platform::reopen_pinned_read(pinned)
}

pub(super) fn read_dir(file: &File) -> Result<Vec<std::ffi::OsString>, &'static str> {
    use std::os::unix::ffi::OsStrExt;

    // A fresh open description has its own directory offset; sharing the
    // caller's offset would make a second listing observe an exhausted walk.
    let duplicate = unsafe {
        libc::openat(
            file.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if duplicate < 0 {
        return Err("list_failed");
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        unsafe {
            libc::close(duplicate);
        }
        return Err("list_failed");
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(std::ffi::OsStr::from_bytes(name).to_os_string());
    }
    unsafe {
        libc::closedir(directory);
    }
    Ok(names)
}

pub(super) fn stat_at(dir: &File, name: &std::ffi::OsStr) -> Result<libc::stat, &'static str> {
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(name.as_bytes()).map_err(|_| "list_failed")?;
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err("list_failed");
    }
    Ok(stat)
}

pub(super) fn identity(file: &File) -> Result<IdentityV1, &'static str> {
    let stat = stat(file)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err("root_invalid");
    }
    Ok(IdentityV1 {
        device: u64::try_from(stat.st_dev).map_err(|_| "stat_failed")?,
        inode: stat.st_ino,
    })
}

pub(super) fn version(file: &File) -> Result<VersionV1, &'static str> {
    let stat = stat(file)?;
    Ok(VersionV1 {
        device: u64::try_from(stat.st_dev).map_err(|_| "stat_failed")?,
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
