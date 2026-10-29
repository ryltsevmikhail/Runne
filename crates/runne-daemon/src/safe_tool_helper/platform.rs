//! Platform-specific pinned-file primitives for the safe tool helper.
//!
//! Linux uses `openat2` with `RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS` and
//! `O_PATH` handles. macOS has neither, so it walks one component at a time
//! with `O_NOFOLLOW` and pins readable descriptors.

#[cfg(target_os = "linux")]
mod imp {
    use super::super::*;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    pub(crate) const O_PATH: i32 = libc::O_PATH;

    pub(crate) fn open_beneath(
        root: &File,
        path: &CStr,
        flags: i32,
        mode: u32,
    ) -> Result<File, &'static str> {
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: u64::from(mode),
            // BENEATH, NO_SYMLINKS, NO_MAGICLINKS
            resolve: 0x08 | 0x04 | 0x02,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err("target_denied");
        }
        Ok(unsafe { File::from_raw_fd(fd as i32) })
    }

    pub(crate) fn reopen_pinned_read(pinned: &File) -> Result<File, &'static str> {
        let proc_path = CString::new(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
            .map_err(|_| "read_denied")?;
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
            // NO_SYMLINKS, NO_MAGICLINKS, including ancestors.
            resolve: 0x04 | 0x02,
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
}

#[cfg(target_os = "macos")]
mod imp {
    use super::super::*;

    /// macOS has no `O_PATH`; pin with a non-blocking read descriptor instead.
    pub(crate) const O_PATH: i32 = libc::O_RDONLY | libc::O_NONBLOCK;

    pub(crate) fn open_beneath(
        root: &File,
        path: &CStr,
        flags: i32,
        mode: u32,
    ) -> Result<File, &'static str> {
        let mut components = path.to_bytes().split(|byte| *byte == b'/').peekable();
        let mut current = root.try_clone().map_err(|_| "target_denied")?;
        while let Some(component) = components.next() {
            if component == b".." {
                // Linux gets this guarantee from `RESOLVE_BENEATH`; refuse it
                // here so a future caller cannot escape the pinned root.
                return Err("target_denied");
            }
            if component.is_empty() || component == b"." {
                continue;
            }
            let name = CString::new(component).map_err(|_| "path_denied")?;
            let leaf = components.peek().is_none();
            let (open_flags, open_mode) = if leaf {
                (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, mode)
            } else {
                (
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                )
            };
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    open_flags,
                    open_mode as libc::c_uint,
                )
            };
            if fd < 0 {
                return Err("target_denied");
            }
            current = unsafe { File::from_raw_fd(fd) };
        }
        Ok(current)
    }

    pub(crate) fn reopen_pinned_read(pinned: &File) -> Result<File, &'static str> {
        pinned.try_clone().map_err(|_| "read_denied")
    }

    /// Mount namespaces are inherited per process on macOS; the held root is
    /// already bound to this invocation.
    pub(crate) fn namespace_root(root: &File) -> Result<File, &'static str> {
        root.try_clone().map_err(|_| "target_denied")
    }
}

pub(crate) use imp::{O_PATH, namespace_root, open_beneath, reopen_pinned_read};
