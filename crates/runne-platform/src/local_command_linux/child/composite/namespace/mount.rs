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
    unsafe { libc::close(fsfd) };
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
    unsafe { libc::close(mount_fd) };
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
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    }
}

pub(super) unsafe fn mask_path(path: *const libc::c_char) -> i32 {
    unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            path,
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            c"mode=755".as_ptr().cast(),
        )
    }
}

pub(super) unsafe fn mount_private_proc() -> i32 {
    unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            c"hidepid=4,subset=pid".as_ptr().cast(),
        )
    }
}

pub(super) unsafe fn verify_single_link_files(files: &[i32]) -> i32 {
    for fd in files {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(*fd, &mut stat) } != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_nlink != 1
        {
            return -1;
        }
    }
    0
}
