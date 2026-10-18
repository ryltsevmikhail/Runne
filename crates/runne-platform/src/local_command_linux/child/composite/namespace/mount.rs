use crate::local_command_linux::LinuxCommandError;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

pub(super) unsafe fn mask_tree_fd(target: *const libc::c_char) -> i32 {
    let fsfd = unsafe { libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), 0usize) as i32 };
    if fsfd < 0 {
        return -1;
    }
    let configured = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fsfd,
            1i32,
            c"mode".as_ptr(),
            c"000".as_ptr(),
            0i32,
        )
    };
    let created = unsafe { libc::syscall(libc::SYS_fsconfig, fsfd, 6i32, 0usize, 0usize, 0i32) };
    let mount_fd = unsafe { libc::syscall(libc::SYS_fsmount, fsfd, 0i32, 0i32) as i32 };
    unsafe { libc::syscall(libc::SYS_close, fsfd) };
    if configured != 0 {
        return -1;
    }
    if created != 0 {
        return -1;
    }
    if mount_fd < 0 {
        return -1;
    }
    let moved = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount_fd,
            c"".as_ptr(),
            libc::AT_FDCWD,
            target,
            0x4usize,
        )
    };
    unsafe { libc::syscall(libc::SYS_close, mount_fd) };
    if moved != 0 {
        return -1;
    }
    0
}

pub(super) fn write_map(path: &str, text: &str) -> Result<(), LinuxCommandError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| LinuxCommandError::Unavailable)?;
    file.write_all(text.as_bytes())
        .map_err(|_| LinuxCommandError::Unavailable)
}

pub(super) unsafe fn make_mounts_private() -> i32 {
    unsafe {
        libc::syscall(
            libc::SYS_mount,
            std::ptr::null::<libc::c_void>(),
            c"/".as_ptr(),
            std::ptr::null::<libc::c_char>(),
            (libc::MS_REC | libc::MS_PRIVATE) as usize,
            std::ptr::null::<libc::c_void>(),
        ) as i32
    }
}

pub(super) unsafe fn mask_path(path: *const libc::c_char) -> i32 {
    unsafe {
        libc::syscall(
            libc::SYS_mount,
            c"tmpfs".as_ptr(),
            path,
            c"tmpfs".as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
            c"mode=755".as_ptr(),
        ) as i32
    }
}

pub(super) unsafe fn mount_private_proc() -> i32 {
    unsafe {
        libc::syscall(
            libc::SYS_mount,
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
            c"hidepid=4,subset=pid".as_ptr(),
        ) as i32
    }
}

/// Published Linux UAPI `statx` request/result mask bits
/// (include/uapi/linux/stat.h): STATX_TYPE = 0x0001, STATX_NLINK = 0x0004.
const STATX_TYPE: u32 = 0x0001;
const STATX_NLINK: u32 = 0x0004;

/// Private fixed-width mirror of the Linux UAPI `struct statx`
/// (include/uapi/linux/stat.h) for the raw child-side syscall.
///
/// One layout serves every advertised Linux target ABI (x86_64 and i686, gnu
/// and musl): all widths are fixed, and on i686 natural C alignment still
/// keeps every 64-bit field at an 8-byte offset, so field offsets coincide
/// with x86_64. The crate must not depend on libc's own `struct statx` /
/// `STATX_*` symbols: libc only exposes them behind a gnu or musl_v1_2_3
/// opt-in, which plain `x86_64-unknown-linux-musl` builds do not have. The
/// trailing remainder covers the four 16-byte timestamps, rdev/dev pairs,
/// mnt_id, direct-I/O, atomic-write and reserved tail, keeping the total
/// exactly 256 bytes so the kernel never writes out of bounds.
#[repr(C, align(8))]
struct RawStatx {
    mask: u32,
    blksize: u32,
    attributes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    spare0: u16,
    ino: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    rest: [u64; 24],
}

/// Raw held-descriptor single-link regular-file check through the fixed
/// Linux UAPI `statx` layout.
///
/// The descriptor itself is the identity (AT_EMPTY_PATH, no path reopen, no
/// symlink escape), and unlike `fstat` one layout is valid on every supported
/// Linux target, so no per-target struct translation runs inside the forked
/// child. Missing mask bits fail closed.
pub(super) unsafe fn verify_single_link_files(files: &[i32]) -> i32 {
    const WANTED: u32 = STATX_TYPE | STATX_NLINK;
    for fd in files {
        // The kernel clears and fills the whole buffer; nothing is read
        // unless the syscall succeeded, so the child performs no buffer
        // initialization or struct move at all (no memset, memcpy, or other
        // libc dependency: the only call is the raw syscall slot).
        let mut statx = std::mem::MaybeUninit::<RawStatx>::uninit();
        let raw = statx.as_mut_ptr();
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                *fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                WANTED,
                raw,
            )
        };
        if result != 0 {
            return -1;
        }
        // SAFETY: the successful raw statx call filled the buffer.
        if unsafe { (*raw).mask } & WANTED != WANTED
            || unsafe { (*raw).mode } & (libc::S_IFMT as u16) != libc::S_IFREG as u16
            || unsafe { (*raw).nlink } != 1
        {
            return -1;
        }
    }
    0
}

#[cfg(test)]
mod statx_layout_tests {
    //! Literal UAPI pins: these numeric offsets are the published
    //! `include/uapi/linux/stat.h` layout, identical on x86_64 and i686
    //! (natural C alignment keeps every u64 at an 8-byte offset on both), so
    //! the raw child call reads the same fields the kernel wrote on every
    //! supported target. Expected values are literal kernel constants, never
    //! derived from the Rust fields themselves.
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn statx_uapi_size_and_field_offsets_are_pinned() {
        assert_eq!(std::mem::size_of::<RawStatx>(), 256);
        assert_eq!(std::mem::align_of::<RawStatx>(), 8);
        assert_eq!(std::mem::offset_of!(RawStatx, mask), 0);
        assert_eq!(std::mem::offset_of!(RawStatx, nlink), 16);
        assert_eq!(std::mem::offset_of!(RawStatx, mode), 28);
        assert_eq!(STATX_TYPE, 0x0001);
        assert_eq!(STATX_NLINK, 0x0004);
    }

    #[test]
    fn verify_accepts_held_regular_file_with_single_link() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("regular");
        std::fs::write(&file, b"payload").expect("write");
        let path = std::ffi::CString::new(file.as_os_str().as_bytes()).expect("cstr");
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        assert_eq!(unsafe { verify_single_link_files(&[fd]) }, 0);
        unsafe { libc::close(fd) };
    }

    #[test]
    fn verify_rejects_file_with_extra_hard_link() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("linked");
        std::fs::write(&file, b"payload").expect("write");
        let alias = dir.path().join("alias");
        let path = std::ffi::CString::new(file.as_os_str().as_bytes()).expect("cstr");
        let alias_path = std::ffi::CString::new(alias.as_os_str().as_bytes()).expect("cstr");
        assert_eq!(unsafe { libc::link(path.as_ptr(), alias_path.as_ptr()) }, 0);
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        assert_eq!(unsafe { verify_single_link_files(&[fd]) }, -1);
        unsafe { libc::close(fd) };
    }

    #[test]
    fn verify_rejects_non_regular_descriptor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = std::ffi::CString::new(dir.path().as_os_str().as_bytes()).expect("cstr");
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        assert_eq!(unsafe { verify_single_link_files(&[fd]) }, -1);
        unsafe { libc::close(fd) };
    }
}
