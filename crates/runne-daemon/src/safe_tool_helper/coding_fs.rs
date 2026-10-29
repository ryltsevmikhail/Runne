use super::*;
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub(crate) fn open(root: &File, path: &str, flags: i32) -> Result<File, &'static str> {
    if !coding_arguments::valid_relative(path, true) {
        return Err("path_denied");
    }
    let name = CString::new(path).map_err(|_| "path_denied")?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: if flags & libc::O_CREAT != 0 { 0o600 } else { 0 },
        resolve: 0x08 | 0x04 | 0x02,
    }; // BENEATH, NO_SYMLINKS, NO_MAGICLINKS
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err("target_denied");
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
pub(crate) fn snapshot(
    root: &File,
    path: &str,
    directory: bool,
) -> Result<VersionV1, &'static str> {
    let file = open(root, path, libc::O_PATH)?;
    if directory {
        identity(&file)?;
    } else if !regular_single(&file)? {
        return Err("target_denied");
    }
    let target = version(&file)?;
    if !directory && target.size > MAX_CONTENT as u64 {
        return Err("content_bound");
    }
    Ok(target)
}
pub(crate) fn capture(
    root: &File,
    tool: &str,
    path: &str,
) -> Result<Option<VersionV1>, &'static str> {
    if tool == "workspace.file.create_new" {
        let (parent, leaf) = path.rsplit_once('/').unwrap_or((".", path));
        let directory = open(root, parent, libc::O_PATH | libc::O_DIRECTORY)?;
        let name = CString::new(leaf).map_err(|_| "path_denied")?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
            return Err("target_exists");
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err("target_denied");
        }
        return Ok(None);
    }
    snapshot(
        root,
        path,
        matches!(
            tool,
            "workspace.files.list" | "workspace.files.search" | "workspace.command.run"
        ),
    )
    .map(Some)
}
pub(crate) fn bounded_read(root: &File, path: &str) -> Result<Vec<u8>, &'static str> {
    let file = open(root, path, libc::O_RDONLY | libc::O_NONBLOCK)?;
    if !regular_single(&file)? {
        return Err("target_denied");
    }
    let before = version(&file)?;
    let bytes = read_bounded(
        &file,
        usize::try_from(before.size).map_err(|_| "content_bound")?,
    )?;
    if before != version(&file)? {
        return Err("target_changed");
    }
    Ok(bytes)
}

/// Rebind the held root to this mount namespace without changing its authority.
/// An inherited SCM_RIGHTS descriptor can retain an unreachable parent mount,
/// forcing getcwd to walk ancestors that the filesystem policy forbids reading.
pub(crate) fn namespace_root(root: &File) -> Result<File, &'static str> {
    use std::os::unix::ffi::OsStrExt;
    let expected = identity(root)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", root.as_raw_fd()))
        .map_err(|_| "target_denied")?;
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4096 {
        return Err("target_denied");
    }
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| "target_denied")?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: 0x04 | 0x02, // NO_SYMLINKS, NO_MAGICLINKS, including ancestors.
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err("target_denied");
    }
    let rebound = unsafe { File::from_raw_fd(raw as i32) };
    if identity(&rebound)? != expected || identity(root)? != expected {
        return Err("target_changed");
    }
    Ok(rebound)
}
