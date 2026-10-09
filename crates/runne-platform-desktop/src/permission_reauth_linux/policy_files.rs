use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

pub(super) struct CapturedFile {
    path: String,
    pub(super) contents: Vec<u8>,
    dev: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

pub(super) fn capture(path: &str, maximum_bytes: u64) -> Result<CapturedFile, ()> {
    let path = Path::new(path);
    let before = secure_metadata(path)?;
    if before.size() > maximum_bytes {
        return Err(());
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    require_same_file(&before, &opened)?;
    require_secure_file(&opened)?;
    let capacity = usize::try_from(opened.size().min(maximum_bytes)).map_err(|_| ())?;
    let mut contents = Vec::with_capacity(capacity);
    (&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut contents)
        .map_err(|_| ())?;
    if u64::try_from(contents.len()).map_err(|_| ())? > maximum_bytes {
        return Err(());
    }
    let after_fd = file.metadata().map_err(|_| ())?;
    let after_path = secure_metadata(path)?;
    require_same_file(&opened, &after_fd)?;
    require_same_file(&opened, &after_path)?;
    Ok(CapturedFile {
        path: path.to_str().ok_or(())?.to_owned(),
        contents,
        dev: opened.dev(),
        inode: opened.ino(),
        uid: opened.uid(),
        gid: opened.gid(),
        mode: opened.mode(),
        size: opened.size(),
        mtime: opened.mtime(),
        mtime_nsec: opened.mtime_nsec(),
        ctime: opened.ctime(),
        ctime_nsec: opened.ctime_nsec(),
    })
}

fn secure_metadata(path: &Path) -> Result<fs::Metadata, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    let components: Vec<Component<'_>> = path.components().collect();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|_| ())?;
        let is_final = index + 1 == components.len();
        if is_final {
            require_secure_file(&metadata)?;
        } else {
            require_secure_directory(&metadata)?;
        }
    }
    fs::symlink_metadata(path).map_err(|_| ())
}

fn require_secure_directory(metadata: &fs::Metadata) -> Result<(), ()> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(());
    }
    Ok(())
}

fn require_secure_file(metadata: &fs::Metadata) -> Result<(), ()> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(());
    }
    Ok(())
}

fn require_same_file(left: &fs::Metadata, right: &fs::Metadata) -> Result<(), ()> {
    if left.dev() != right.dev()
        || left.ino() != right.ino()
        || left.uid() != right.uid()
        || left.gid() != right.gid()
        || left.mode() != right.mode()
        || left.size() != right.size()
        || left.mtime() != right.mtime()
        || left.mtime_nsec() != right.mtime_nsec()
        || left.ctime() != right.ctime()
        || left.ctime_nsec() != right.ctime_nsec()
    {
        return Err(());
    }
    Ok(())
}

pub(super) fn fingerprint(entries: &[CapturedFile]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"runne.d21.linux-pam-qualified-policy.v1\0");
    for entry in entries {
        let path = entry.path.as_bytes();
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path);
        for value in [
            entry.dev,
            entry.inode,
            u64::from(entry.uid),
            u64::from(entry.gid),
            u64::from(entry.mode),
            entry.size,
        ] {
            digest.update(value.to_le_bytes());
        }
        for value in [entry.mtime, entry.mtime_nsec, entry.ctime, entry.ctime_nsec] {
            digest.update(value.to_le_bytes());
        }
        digest.update(Sha256::digest(&entry.contents));
    }
    digest.finalize().into()
}

pub(super) fn same_fingerprint(expected: [u8; 32], current: [u8; 32]) -> bool {
    expected == current
}

#[cfg(test)]
pub(super) const fn test_secure_mode(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}
