pub fn open_watch(path: &std::path::Path) -> std::fs::File {
    open_watch_for(path, libc::IN_OPEN)
}

pub fn open_create_watch(path: &std::path::Path) -> std::fs::File {
    open_watch_for(path, libc::IN_CREATE)
}

fn open_watch_for(path: &std::path::Path, mask: u32) -> std::fs::File {
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    assert!(fd >= 0, "create filesystem observer");
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("watch path");
    let watch = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) };
    assert!(watch >= 0, "watch filesystem event");
    unsafe { std::fs::File::from_raw_fd(fd) }
}

pub fn read_watch(file: &std::fs::File) -> usize {
    use std::os::fd::AsRawFd as _;
    let mut events = [0_u8; 256];
    let read = unsafe { libc::read(file.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
    if read < 0 {
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
        0
    } else {
        read as usize
    }
}

pub fn count_watch_mask(file: &std::fs::File, mask: u32) -> usize {
    use std::os::fd::AsRawFd as _;
    let mut bytes = [0_u8; 4096];
    let mut matched = 0_usize;
    loop {
        let read = unsafe { libc::read(file.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if read < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            return matched;
        }
        if read == 0 {
            return matched;
        }
        let mut offset = 0_usize;
        while offset < read as usize {
            const FIXED: usize = std::mem::size_of::<libc::inotify_event>();
            assert!(read as usize - offset >= FIXED, "bounded inotify header");
            let event_mask = u32::from_ne_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
            let name_length =
                u32::from_ne_bytes(bytes[offset + 12..offset + 16].try_into().unwrap()) as usize;
            let event_length = FIXED
                .checked_add(name_length)
                .expect("inotify event length");
            assert!(
                event_length <= read as usize - offset,
                "bounded inotify event body"
            );
            matched += usize::from(event_mask & mask != 0);
            offset += event_length;
        }
    }
}
