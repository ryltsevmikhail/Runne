use std::{
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::Path,
    time::Duration,
};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) length: u64,
    pub(super) modified_seconds: i64,
    pub(super) modified_nanoseconds: i64,
    pub(super) changed_seconds: i64,
    pub(super) changed_nanoseconds: i64,
}

pub(super) fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

pub(super) async fn wait_entered(directory: &Path) {
    let entered = directory.join("create.entered");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        if let Ok(metadata) = std::fs::symlink_metadata(&entered) {
            assert!(metadata.file_type().is_file());
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.mode() & 0o022, 0);
            if std::fs::read(&entered).is_ok_and(|bytes| bytes == b"entered\n") {
                return;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "helper barrier was not entered"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub(super) fn create_release(directory: &Path) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options
        .open(directory.join("create.release"))
        .expect("create exclusive race release marker");
}

pub(super) fn named_create_events(watch: &File, name: &str) -> usize {
    let mut events = [0_u8; 4096];
    let mut count = 0;
    loop {
        let read =
            unsafe { libc::read(watch.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
        if read < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            return count;
        }
        if read == 0 {
            return count;
        }
        let mut offset = 0;
        while offset < read as usize {
            let mask = u32::from_ne_bytes(events[offset + 4..offset + 8].try_into().unwrap());
            let name_len =
                u32::from_ne_bytes(events[offset + 12..offset + 16].try_into().unwrap()) as usize;
            let start = offset + std::mem::size_of::<libc::inotify_event>();
            let event_name = events[start..start + name_len]
                .iter()
                .copied()
                .take_while(|byte| *byte != 0)
                .collect::<Vec<_>>();
            count += usize::from(mask & libc::IN_CREATE != 0 && event_name == name.as_bytes());
            offset = start + name_len;
        }
    }
}

pub(super) fn open_canary_watch(path: &Path) -> File {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("canary watch path");
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    assert!(fd >= 0, "create canary filesystem observer");
    let watch = unsafe {
        libc::inotify_add_watch(
            fd,
            path.as_ptr(),
            libc::IN_OPEN | libc::IN_ACCESS | libc::IN_MODIFY,
        )
    };
    assert!(watch >= 0, "watch outside canary events");
    unsafe { File::from_raw_fd(fd) }
}

pub(super) fn drain_canary_events(watch: &File) -> (usize, usize, usize) {
    let mut events = [0_u8; 4096];
    let (mut opened, mut accessed, mut modified) = (0, 0, 0);
    loop {
        let read =
            unsafe { libc::read(watch.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
        if read < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            return (opened, accessed, modified);
        }
        if read == 0 {
            return (opened, accessed, modified);
        }
        let mut offset = 0;
        while offset < read as usize {
            let mask = u32::from_ne_bytes(events[offset + 4..offset + 8].try_into().unwrap());
            opened += usize::from(mask & libc::IN_OPEN != 0);
            accessed += usize::from(mask & libc::IN_ACCESS != 0);
            modified += usize::from(mask & libc::IN_MODIFY != 0);
            let name_len =
                u32::from_ne_bytes(events[offset + 12..offset + 16].try_into().unwrap()) as usize;
            offset += std::mem::size_of::<libc::inotify_event>() + name_len;
        }
    }
}
