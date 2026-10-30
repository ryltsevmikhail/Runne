//! Guest-only bounded diagnostics and held/named joins under the closed fixture.
//! Final-component NOFOLLOW is not an adversarial intermediate-path theorem.
use super::clock::Deadline;
use super::model::{RootIdentity, root_name};
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) fn bounded(path: &Path, cap: usize, deadline: Deadline) -> String {
    deadline.check();
    assert!(cap > 0 && cap <= 65536);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .unwrap();
    assert!(file.metadata().unwrap().is_file());
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        deadline.check();
        let size = (cap + 1 - bytes.len()).min(chunk.len());
        let n = match file.read(&mut chunk[..size]) {
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => panic!("bounded guest diagnostic: {error}"),
        };
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        assert!(bytes.len() <= cap, "guest diagnostic cap");
    }
    deadline.check();
    String::from_utf8(bytes).unwrap()
}

fn identity(meta: &Metadata) -> RootIdentity {
    assert!(meta.is_dir());
    let value = RootIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
    };
    value.validate();
    value
}

pub(super) struct HeldRoot {
    pub path: PathBuf,
    pub identity: RootIdentity,
    pub file: File,
}

impl HeldRoot {
    pub(super) fn open(path: PathBuf, prefix: &str, deadline: Deadline) -> Self {
        deadline.check();
        root_name(&path, prefix);
        let before = identity(&std::fs::symlink_metadata(&path).unwrap());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        assert_eq!(identity(&file.metadata().unwrap()), before);
        let value = Self {
            path,
            identity: before,
            file,
        };
        value.check(deadline);
        value
    }

    pub(super) fn check(&self, deadline: Deadline) {
        deadline.check();
        assert_eq!(identity(&self.file.metadata().unwrap()), self.identity);
        assert_eq!(
            identity(&std::fs::symlink_metadata(&self.path).unwrap()),
            self.identity
        );
        assert_eq!(std::fs::canonicalize(&self.path).unwrap(), self.path);
        deadline.check();
    }
}

pub(super) fn ram_device(deadline: Deadline) -> u64 {
    let path = Path::new("/dev/shm");
    let meta = std::fs::symlink_metadata(path).unwrap();
    assert!(meta.is_dir());
    assert_eq!((meta.uid(), meta.gid(), meta.mode()), (0, 0, 0o41777));
    assert_eq!(std::fs::canonicalize(path).unwrap(), path);
    let info = bounded(Path::new("/proc/self/mountinfo"), 65536, deadline);
    let mut count = 0;
    for line in info.lines() {
        let (left, right) = line.split_once(" - ").unwrap();
        let fields: Vec<_> = left.split_ascii_whitespace().collect();
        assert!(fields.len() >= 6);
        if fields[4] != "/dev/shm" {
            continue;
        }
        count += 1;
        assert_eq!(fields[3], "/");
        assert_eq!(right.split_ascii_whitespace().next(), Some("tmpfs"));
        let dev = meta.dev();
        let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
        let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
        assert_eq!(fields[2], format!("{major}:{minor}"));
    }
    assert_eq!(count, 1, "unique guest RAM mount");
    deadline.check();
    // Capacity is an init contract; this diagnostic does not attest its limit.
    meta.dev()
}
