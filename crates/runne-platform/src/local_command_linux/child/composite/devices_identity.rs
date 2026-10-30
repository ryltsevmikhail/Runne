//! Fixed-width Linux statx identity comparison; raw post-clone syscalls only.
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
    timestamps: [u64; 8],
    rdev_major: u32,
    rdev_minor: u32,
    dev_major: u32,
    dev_minor: u32,
    rest: [u64; 14],
}
pub(super) unsafe fn matches(held_path: *const libc::c_char, mount_fd: i32) -> bool {
    const WANTED: u32 = 0x101; // STATX_TYPE | STATX_INO; device IDs are always returned.
    let mut held = std::mem::MaybeUninit::<RawStatx>::uninit();
    let mut fresh = std::mem::MaybeUninit::<RawStatx>::uninit();
    let held = held.as_mut_ptr();
    let fresh = fresh.as_mut_ptr();
    if unsafe { libc::syscall(libc::SYS_statx, libc::AT_FDCWD, held_path, 0, WANTED, held) } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_statx,
                mount_fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                WANTED,
                fresh,
            )
        } != 0
    {
        return false;
    }
    // Successful statx fills the complete buffer; read scalar fields in place,
    // avoiding libc memset/memcpy dependencies in the cloned child.
    unsafe {
        (*held).mask & WANTED == WANTED
            && (*fresh).mask & WANTED == WANTED
            && (*held).mode & libc::S_IFMT as u16 == libc::S_IFCHR as u16
            && (*fresh).mode & libc::S_IFMT as u16 == libc::S_IFCHR as u16
            && (*held).ino == (*fresh).ino
            && (*held).dev_major == (*fresh).dev_major
            && (*held).dev_minor == (*fresh).dev_minor
            && (*held).rdev_major == (*fresh).rdev_major
            && (*held).rdev_minor == (*fresh).rdev_minor
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn statx_device_identity_layout_is_linux_uapi() {
        assert_eq!(std::mem::size_of::<RawStatx>(), 256);
        assert_eq!(std::mem::offset_of!(RawStatx, mode), 28);
        assert_eq!(std::mem::offset_of!(RawStatx, ino), 32);
        assert_eq!(std::mem::offset_of!(RawStatx, rdev_major), 128);
        assert_eq!(std::mem::offset_of!(RawStatx, dev_major), 136);
    }
    #[test]
    fn different_character_device_cannot_replace_held_identity() {
        use std::os::fd::AsRawFd;
        let null = std::fs::File::open("/dev/null").unwrap();
        let zero = std::fs::File::open("/dev/zero").unwrap();
        assert!(unsafe { matches(c"/dev/null".as_ptr(), null.as_raw_fd()) });
        assert!(!unsafe { matches(c"/dev/null".as_ptr(), zero.as_raw_fd()) });
    }
}
